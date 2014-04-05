# -*- coding: binary -*-
require 'thread'

module Msf

###
#
# The purpose of the session manager is to keep track of sessions that are
# created during the course of a framework instance's lifetime.  When
# exploits succeed, the payloads they use will create a session object,
# where applicable, there will implement zero or more of the core
# supplied interfaces for interacting with that session.  For instance,
# if the payload supports reading and writing from an executed process,
# the session would implement SimpleCommandShell in a method that is
# applicable to the way that the command interpreter is communicated
# with.
#
###
class SessionManager < Hash

  include Framework::Offspring

  LAST_SEEN_INTERVAL  = 60 * 2.5
  SCHEDULER_THREAD_COUNT = 5

  def initialize(framework)
    self.framework = framework
    self.sid_pool  = 0
    self.mutex = Mutex.new
    self.scheduler_queue = ::Queue.new
    self.initialize_scheduler_threads

    self.monitor_thread = framework.threads.spawn("SessionManager", true) do
      last_seen_timer = Time.now.utc

      respawn_max = 30
      respawn_cnt = 0

      begin
      while true

        #
        # Process incoming data from all stream-based sessions and queue the
        # data into the associated ring buffers.
        #
        rings = values.select{|s| s.respond_to?(:ring) and s.ring and s.rstream }
        ready = ::IO.select(rings.map{|s| s.rstream}, nil, nil, 0.5) || [[],[],[]]

        ready[0].each do |fd|
          s = rings.select{|s| s.rstream == fd}.first
          next if not s

          begin
            buff = fd.get_once(-1)
            if buff
              # Store the data in the associated ring
              s.ring.store_data(buff)

              # Store the session event into the database.
              # Rescue anything the event handlers raise so they
              # don't break our session.
              framework.events.on_session_output(s, buff) rescue nil
            end
          rescue ::Exception => e
            wlog("Exception reading from Session #{s.sid}: #{e.class} #{e}")
            unless e.kind_of? EOFError
              # Don't bother with a call stack if it's just a
              # normal EOF
              dlog("Call Stack\n#{e.backtrace.join("\n")}", 'core', LEV_3)
            end

            # Flush any ring data in the queue
            s.ring.clear_data rescue nil

            # Shut down the socket itself
            s.rstream.close rescue nil

            # Deregister the session
            deregister(s, "Died from #{e.class}")
          end
        end


        #
        # TODO: Call the dispatch entry point of each Meterpreter thread instead of
        #       dedicating specific processing threads to each session
        #


        #
        # Check for closed / dead / terminated sessions
        #
        values.each do |s|
          if not s.alive?
            deregister(s, "Died")
            wlog("Session #{s.sid} has died")
            next
          end
        end

        #
        # Mark all open session as alive every LAST_SEEN_INTERVAL
        #
        if (Time.now.utc - last_seen_timer) >= LAST_SEEN_INTERVAL

          # Update this timer BEFORE processing the session list, this will prevent
          # processing time for large session lists from skewing our update interval.

          last_seen_timer = Time.now.utc
          if framework.db.active
            ::ActiveRecord::Base.connection_pool.with_connection do
              values.each do |s|
                # Update the database entry on a regular basis, marking alive threads
                # as recently seen.  This notifies other framework instances that this
                # session is being maintained.
                if s.db_record
                  s.db_record.last_seen = Time.now.utc
                  s.db_record.save
                end
              end
            end
          end
        end


        #
        # Skip the database cleanup code below if there is no database
        #
        next if not (framework.db and framework.db.active)

        #
        # Clean out any stale sessions that have been orphaned by a dead
        # framework instance.
        #
        ::ActiveRecord::Base.connection_pool.with_connection do |conn|
          ::Mdm::Session.find_all_by_closed_at(nil).each do |db_session|
            if db_session.last_seen.nil? or ((Time.now.utc - db_session.last_seen) > (2*LAST_SEEN_INTERVAL))
              db_session.closed_at    = db_session.last_seen || Time.now.utc
              db_session.close_reason = "Orphaned"
              db_session.save
            end
          end
        end
      end

      #
      # All session management falls apart when any exception is raised to this point. Log it.
      #
      rescue ::Exception => e
        respawn_cnt += 1
        elog("Exception #{respawn_cnt}/#{respawn_max} in monitor thread #{e.class} #{e}")
        elog("Call stack: \n#{e.backtrace.join("\n")}")
        if respawn_cnt < respawn_max
          ::IO.select(nil, nil, nil, 10.0)
          retry
        end
      end
    end
  end

  #
  # Dedicated worker threads for pulling data out of new sessions
  #
  def initialize_scheduler_threads
    self.scheduler_threads = []
    1.upto(SCHEDULER_THREAD_COUNT) do |i|
      self.scheduler_threads << framework.threads.spawn("SessionScheduler-#{i}", true) do
        while true
          item = self.scheduler_queue.pop
          begin
            item.call()
          rescue ::Exception => e
            wlog("Exception in scheduler thread #{e.class} #{e}")
            wlog("Call Stack\n#{e.backtrace.join("\n")}", 'core', LEV_3)
          end
        end
      end
    end
  end

  #
  # Add a new task to the loader thread queue. Task is assumed to be
  # a Proc or another object that responds to call()
  #
  def schedule(task)
    self.scheduler_queue.push(task)
  end

  #
  # Enumerates the sorted list of keys.
  #
  def each_sorted(&block)
    self.keys.sort.each(&block)
  end

  #
  # Overrides the builtin 'each' operator to avoid the following exception on Ruby 1.9.2+
  #    "can't add a new key into hash during iteration"
  # This allows us to register new sessions while other threads are enumerating the
  # session list.
  #
  def each(&block)
    list = []
    self.keys.sort.each do |sidx|
      list << [sidx, self[sidx]]
    end
    list.each(&block)
  end

  #
  # Registers the supplied session object with the framework and returns
  # a unique session identifier to the caller.
  #
  def register(session)
    if (session.sid)
      wlog("registered session passed to register again (sid #{session.sid}).")
      return nil
    end

    next_sid = allocate_sid

    # Initialize the session's sid and framework instance pointer
    session.sid       = next_sid
    session.framework = framework

    # Only register if the session allows for it
    if session.register?
      # Insert the session into the session hash table
      self[next_sid.to_i] = session

      # Notify the framework that we have a new session opening up...
      # Don't let errant event handlers kill our session
      begin
        framework.events.on_session_open(session)
      rescue ::Exception => e
        wlog("Exception in on_session_open event handler: #{e.class}: #{e}")
        wlog("Call Stack\n#{e.backtrace.join("\n")}")
      end

      if session.respond_to?("console")
        session.console.on_command_proc = Proc.new { |command, error| framework.events.on_session_command(session, command) }
        session.console.on_print_proc = Proc.new { |output| framework.events.on_session_output(session, output) }
      end
    end

    return next_sid
  end

  #
  # Deregisters the supplied session object with the framework.
  #
  def deregister(session, reason='')
    return if not session.register?

    if (session.dead? and not self[session.sid.to_i])
      return
    end

    # Tell the framework that we have a parting session
    framework.events.on_session_close(session, reason) rescue nil

    # If this session implements the comm interface, remove any routes
    # that have been created for it.
    if (session.kind_of?(Msf::Session::Comm))
      Rex::Socket::SwitchBoard.remove_by_comm(session)
    end

    # Remove it from the hash
    self.delete(session.sid.to_i)

    # Mark the session as dead
    session.alive = false

    # Close it down
    session.cleanup
  end

  #
  # Returns the session associated with the supplied sid, if any.
  #
  def get(sid)
    session = nil
    sid = sid.to_i

    if sid > 0
      session = self[sid]
    elsif sid == -1
      sid = self.keys.sort[-1]
      session = self[sid]
    end

    session
  end

  #
  # Allocates the next Session ID
  #
  def allocate_sid
    self.mutex.synchronize do
      self.sid_pool += 1
    end
  end

protected

  attr_accessor :sid_pool, :sessions # :nodoc:
  attr_accessor :monitor_thread # :nodoc:
  attr_accessor :scheduler_threads # :nodoc:
  attr_accessor :scheduler_queue # :nodoc:
  attr_accessor :mutex # :nodoc:

end

end

