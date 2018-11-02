# -*- coding: binary -*-
require 'msf/core/plugin'

=begin
require 'active_record'
#
# This monkeypatch can help to diagnose errors involving connection pool
# exhaustion and other strange ActiveRecord including errors like:
#
#   DEPRECATION WARNING: Database connections will not be closed automatically, please close your
#   database connection at the end of the thread by calling `close` on your
#   connection.  For example: ActiveRecord::Base.connection.close
#
# and
#
#   ActiveRecord::StatementInvalid NoMethodError: undefined method `fields' for nil:NilClass: SELECT  "workspaces".* FROM "workspaces"  WHERE "workspaces"."id" = 24 LIMIT 1
#
#
# Based on this code: https://gist.github.com/1364551 linked here:
# http://bibwild.wordpress.com/2011/11/14/multi-threading-in-rails-activerecord-3-0-3-1/
module ActiveRecord
  class Base
    class << self
      def connection
        unless connection_pool.active_connection?
          $stdout.puts("AR::B.connection implicit checkout")
          $stdout.puts(caller.join("\n"))
          raise ImplicitConnectionForbiddenError.new("Implicit ActiveRecord checkout attempted!")
        end
        retrieve_connection
      end
    end
  end
  class ImplicitConnectionForbiddenError < ActiveRecord::ConnectionTimeoutError ; end
end
=end


module Msf

###
#
# This class manages the threads spawned by the framework object, this provides some additional
# features over standard ruby threads.
#
###
class ThreadManager < Array

  include Framework::Offspring

  attr_accessor :monitor

  #
  # Initializes the thread manager.
  #
  def initialize(framework)
    self.framework = framework
    self.monitor   = spawn_monitor

    # XXX: Preserve Ruby < 2.5 thread exception reporting behavior
    # https://ruby-doc.org/core-2.5.0/Thread.html#method-c-report_on_exception
    if Thread.method_defined?(:report_on_exception=)
      Thread.report_on_exception = false
    end
  end

  #
  # Spawns a monitor thread for removing dead threads
  #
  def spawn_monitor
    ::Thread.new do
      begin

      ::Thread.current[:tm_name] = "Thread Monitor"
      ::Thread.current[:tm_crit] = true

      while true
        ::IO.select(nil, nil, nil, 1.0)
        self.each_index do |i|
          state = self[i].alive? rescue false
          self[i] = nil if not state
        end
        self.delete(nil)
      end

      rescue ::Exception => e
        elog("thread monitor: #{e} #{e.backtrace} source:#{self[:tm_call].inspect}")
      end
    end
  end

  #
  # Spawns a new thread
  #
  def spawn(name, crit, *args, &block)
    t = nil

    if block
      t = ::Thread.new(name, crit, caller, block, *args) do |*argv|
        ::Thread.current[:tm_name] = argv.shift.to_s
        ::Thread.current[:tm_crit] = argv.shift
        ::Thread.current[:tm_call] = argv.shift
        ::Thread.current[:tm_time] = Time.now

        begin
          argv.shift.call(*argv)
        rescue ::Exception => e
          elog(
              "thread exception: #{::Thread.current[:tm_name]}  critical=#{::Thread.current[:tm_crit]}  " \
              "error: #{e.class} #{e}\n" \
              "  source:\n" \
              "    #{::Thread.current[:tm_call].join "\n    "}"
          )
          elog("Call Stack\n#{e.backtrace.join("\n")}")
          raise e
        ensure
          if framework.db && framework.db.active && framework.db.is_local?
            # NOTE: despite the Deprecation Warning's advice, this should *NOT*
            # be ActiveRecord::Base.connection.close which causes unrelated
            # threads to raise ActiveRecord::StatementInvalid exceptions at
            # some point in the future, presumably due to the pool manager
            # believing that the connection is still usable and handing it out
            # to another thread.
            ::ActiveRecord::Base.connection_pool.release_connection
          end
        end
      end
    else
      t = ::Thread.new(name, crit, caller, *args) do |*argv|
        ::Thread.current[:tm_name] = argv.shift
        ::Thread.current[:tm_crit] = argv.shift
        ::Thread.current[:tm_call] = argv.shift
        ::Thread.current[:tm_time] = Time.now
        # Calling spawn without a block means we cannot force a database
        # connection release when the thread completes, so doing so can
        # potentially use up all database resources and starve all subsequent
        # threads that make use of the database. Log a warning so we can track
        # down this kind of usage.
        dlog("Thread spawned without a block!")
        dlog("Call stack: \n#{::Thread.current[:tm_call].join("\n")}")
      end
    end

    self << t
    t
  end

  #
  # Registers an existing thread
  #
  def register(t, name, crit)
    t[:tm_name] = name
    t[:tm_crit] = crit
    t[:tm_call] = caller
    t[:tm_time] = Time.now
    self << t
    t
  end

  #
  # Updates an existing thread
  #
  def update(ut, name, crit)
    ti = nil
    self.each_index do |i|
      tt = self[i]
      next if not tt
      if ut.__id__ == tt.__id__
        ti = i
        break
      end
    end

    t = self[ti]
    if not t
      raise RuntimeError, "Thread not found"
    end

    t[:tm_name] = name
    t[:tm_crit] = crit
    t
  end

  #
  # Kills a thread by index
  #
  def kill(idx)
    self[idx].kill rescue false
  end

end

end
