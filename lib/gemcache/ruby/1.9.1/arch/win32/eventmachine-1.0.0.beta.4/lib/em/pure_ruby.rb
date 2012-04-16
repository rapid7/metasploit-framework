#--
#
# Author:: Francis Cianfrocca (gmail: blackhedd)
# Homepage::  http://rubyeventmachine.com
# Date:: 8 Apr 2006
#
# See EventMachine and EventMachine::Connection for documentation and
# usage examples.
#
#----------------------------------------------------------------------------
#
# Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
# Gmail: blackhedd
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of either: 1) the GNU General Public License
# as published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version; or 2) Ruby's License.
#
# See the file COPYING for complete licensing information.
#
#-------------------------------------------------------------------
#
#

# TODO List:
# TCP-connects currently assume non-blocking connect is available- need to
#  degrade automatically on versions of Ruby prior to June 2006.
#

require 'singleton'
require 'forwardable'
require 'socket'
require 'fcntl'
require 'set'

# @private
module EventMachine
  class << self
    # This is mostly useful for automated tests.
    # Return a distinctive symbol so the caller knows whether he's dealing
    # with an extension or with a pure-Ruby library.
    # @private
    def library_type
      :pure_ruby
    end

    # @private
    def initialize_event_machine
      Reactor.instance.initialize_for_run
    end

    # Changed 04Oct06: intervals from the caller are now in milliseconds, but our native-ruby
    # processor still wants them in seconds.
    # @private
    def add_oneshot_timer interval
      Reactor.instance.install_oneshot_timer(interval / 1000)
    end

    # @private
    def run_machine
      Reactor.instance.run
    end

    # @private
    def release_machine
    end

    # @private
    def stop
      Reactor.instance.stop
    end

    # @private
    def connect_server host, port
      bind_connect_server nil, nil, host, port
    end

    # @private
    def bind_connect_server bind_addr, bind_port, host, port
      EvmaTCPClient.connect(bind_addr, bind_port, host, port).uuid
    end

    # @private
    def send_data target, data, datalength
      selectable = Reactor.instance.get_selectable( target ) or raise "unknown send_data target"
      selectable.send_data data
    end


    # The extension version does NOT raise any kind of an error if an attempt is made
    # to close a non-existent connection. Not sure whether we should. For now, we'll
    # raise an error here in that case.
    # @private
    def close_connection target, after_writing
      selectable = Reactor.instance.get_selectable( target ) or raise "unknown close_connection target"
      selectable.schedule_close after_writing
    end

    # @private
    def start_tcp_server host, port
      (s = EvmaTCPServer.start_server host, port) or raise "no acceptor"
      s.uuid
    end

    # @private
    def stop_tcp_server sig
      s = Reactor.instance.get_selectable(sig)
      s.schedule_close
    end

    # @private
    def start_unix_server chain
      (s = EvmaUNIXServer.start_server chain) or raise "no acceptor"
      s.uuid
    end

    # @private
    def connect_unix_server chain
      EvmaUNIXClient.connect(chain).uuid
    end

    # @private
    def signal_loopbreak
      Reactor.instance.signal_loopbreak
    end

    # @private
    def get_peername sig
      selectable = Reactor.instance.get_selectable( sig ) or raise "unknown get_peername target"
      selectable.get_peername
    end

    # @private
    def open_udp_socket host, port
      EvmaUDPSocket.create(host, port).uuid
    end

    # This is currently only for UDP!
    # We need to make it work with unix-domain sockets as well.
    # @private
    def send_datagram target, data, datalength, host, port
      selectable = Reactor.instance.get_selectable( target ) or raise "unknown send_data target"
      selectable.send_datagram data, Socket::pack_sockaddr_in(port, host)
    end


    # Sets reactor quantum in milliseconds. The underlying Reactor function wants a (possibly
    # fractional) number of seconds.
    # @private
    def set_timer_quantum interval
      Reactor.instance.set_timer_quantum(( 1.0 * interval) / 1000.0)
    end

    # This method is a harmless no-op in the pure-Ruby implementation. This is intended to ensure
    # that user code behaves properly across different EM implementations.
    # @private
    def epoll
    end

    # This method is not implemented for pure-Ruby implementation
    # @private
    def ssl?
      false
    end

    # This method is a no-op in the pure-Ruby implementation. We simply return Ruby's built-in
    # per-process file-descriptor limit.
    # @private
    def set_rlimit_nofile n
      1024
    end

    # This method is a harmless no-op in pure Ruby, which doesn't have a built-in limit
    # on the number of available timers.
    # @private
    def set_max_timer_count n
    end

    # @private
    def get_sock_opt signature, level, optname
      selectable = Reactor.instance.get_selectable( signature ) or raise "unknown get_peername target"
      selectable.getsockopt level, optname
    end

    # @private
    def set_sock_opt signature, level, optname, optval
      selectable = Reactor.instance.get_selectable( signature ) or raise "unknown get_peername target"
      selectable.setsockopt level, optname, optval
    end

    # @private
    def send_file_data sig, filename
      sz = File.size(filename)
      raise "file too large" if sz > 32*1024
      data =
        begin
          File.read filename
        rescue
          ""
        end
      send_data sig, data, data.length
    end

    # @private
    def get_outbound_data_size sig
      r = Reactor.instance.get_selectable( sig ) or raise "unknown get_outbound_data_size target"
      r.get_outbound_data_size
    end

    # @private
    def read_keyboard
      EvmaKeyboard.open.uuid
    end

    # @private
    def set_comm_inactivity_timeout sig, tm
      r = Reactor.instance.get_selectable( sig ) or raise "unknown set_comm_inactivity_timeout target"
      r.set_inactivity_timeout tm
    end
  end
end


module EventMachine
  # @private
  class Error < Exception; end
end

module EventMachine
  # @private
  class Connection
    # @private
    def get_outbound_data_size
      EventMachine::get_outbound_data_size @signature
    end
  end
end

module EventMachine

  # Factored out so we can substitute other implementations
  # here if desired, such as the one in ActiveRBAC.
  # @private
  module UuidGenerator
    def self.generate
      @ix ||= 0
      @ix += 1
    end
  end
end


module EventMachine
  # @private
  TimerFired = 100
  # @private
  ConnectionData = 101
  # @private
  ConnectionUnbound = 102
  # @private
  ConnectionAccepted = 103
  # @private
  ConnectionCompleted = 104
  # @private
  LoopbreakSignalled = 105
end

module EventMachine
  # @private
  class Reactor
    include Singleton

    HeartbeatInterval = 2

    attr_reader :current_loop_time

    def initialize
      initialize_for_run
    end

    def install_oneshot_timer interval
      uuid = UuidGenerator::generate
      #@timers << [Time.now + interval, uuid]
      #@timers.sort! {|a,b| a.first <=> b.first}
      @timers.add([Time.now + interval, uuid])
      uuid
    end

    # Called before run, this is a good place to clear out arrays
    # with cruft that may be left over from a previous run.
    # @private
    def initialize_for_run
      @running = false
      @stop_scheduled = false
      @selectables ||= {}; @selectables.clear
      @timers = SortedSet.new # []
      set_timer_quantum(0.1)
      @current_loop_time = Time.now
      @next_heartbeat = @current_loop_time + HeartbeatInterval
    end

    def add_selectable io
      @selectables[io.uuid] = io
    end

    def get_selectable uuid
      @selectables[uuid]
    end

    def run
      raise Error.new( "already running" ) if @running
      @running = true

      begin
        open_loopbreaker

        loop {
          @current_loop_time = Time.now

          break if @stop_scheduled
          run_timers
          break if @stop_scheduled
          crank_selectables
          break if @stop_scheduled
          run_heartbeats
        }
      ensure
        close_loopbreaker
        @selectables.each {|k, io| io.close}
        @selectables.clear

        @running = false
      end

    end

    def run_timers
      @timers.each {|t|
        if t.first <= @current_loop_time
          @timers.delete t
          EventMachine::event_callback "", TimerFired, t.last
        else
          break
        end
      }
      #while @timers.length > 0 and @timers.first.first <= now
      #  t = @timers.shift
      #  EventMachine::event_callback "", TimerFired, t.last
      #end
    end

    def run_heartbeats
      if @next_heartbeat <= @current_loop_time
        @next_heartbeat = @current_loop_time + HeartbeatInterval
        @selectables.each {|k,io| io.heartbeat}
      end
    end

    def crank_selectables
      #$stderr.write 'R'

      readers = @selectables.values.select {|io| io.select_for_reading?}
      writers = @selectables.values.select {|io| io.select_for_writing?}

      s = select( readers, writers, nil, @timer_quantum)

      s and s[1] and s[1].each {|w| w.eventable_write }
      s and s[0] and s[0].each {|r| r.eventable_read }

      @selectables.delete_if {|k,io|
        if io.close_scheduled?
          io.close
          true
        end
      }
    end

    # #stop
    def stop
      raise Error.new( "not running") unless @running
      @stop_scheduled = true
    end

    def open_loopbreaker
      # Can't use an IO.pipe because they can't be set nonselectable in Windows.
      # Pick a random localhost UDP port.
      #@loopbreak_writer.close if @loopbreak_writer
      #rd,@loopbreak_writer = IO.pipe
      @loopbreak_reader = UDPSocket.new
      @loopbreak_writer = UDPSocket.new
      bound = false
      100.times {
        @loopbreak_port = rand(10000) + 40000
        begin
          @loopbreak_reader.bind "localhost", @loopbreak_port
          bound = true
          break
        rescue
        end
      }
      raise "Unable to bind Loopbreaker" unless bound
      LoopbreakReader.new(@loopbreak_reader)
    end

    def close_loopbreaker
      @loopbreak_writer.close
      @loopbreak_writer = nil
    end

    def signal_loopbreak
      #@loopbreak_writer.write '+' if @loopbreak_writer
      @loopbreak_writer.send('+',0,"localhost",@loopbreak_port) if @loopbreak_writer
    end

    def set_timer_quantum interval_in_seconds
      @timer_quantum = interval_in_seconds
    end

  end

end

# @private
class IO
  extend Forwardable
  def_delegator :@my_selectable, :close_scheduled?
  def_delegator :@my_selectable, :select_for_reading?
  def_delegator :@my_selectable, :select_for_writing?
  def_delegator :@my_selectable, :eventable_read
  def_delegator :@my_selectable, :eventable_write
  def_delegator :@my_selectable, :uuid
  def_delegator :@my_selectable, :send_data
  def_delegator :@my_selectable, :schedule_close
  def_delegator :@my_selectable, :get_peername
  def_delegator :@my_selectable, :send_datagram
  def_delegator :@my_selectable, :get_outbound_data_size
  def_delegator :@my_selectable, :set_inactivity_timeout
  def_delegator :@my_selectable, :heartbeat
end

module EventMachine
  # @private
  class Selectable

    attr_reader :io, :uuid

    def initialize io
      @uuid = UuidGenerator.generate
      @io = io
      @last_activity = Reactor.instance.current_loop_time

      if defined?(Fcntl::F_GETFL)
        m = @io.fcntl(Fcntl::F_GETFL, 0)
        @io.fcntl(Fcntl::F_SETFL, Fcntl::O_NONBLOCK | m)
      else
        # Windows doesn't define F_GETFL.
        # It's not very reliable about setting descriptors nonblocking either.
        begin
          s = Socket.for_fd(@io.fileno)
          s.fcntl( Fcntl::F_SETFL, Fcntl::O_NONBLOCK )
        rescue Errno::EINVAL, Errno::EBADF
          warn "Serious error: unable to set descriptor non-blocking"
        end
      end
      # TODO, should set CLOEXEC on Unix?

      @close_scheduled = false
      @close_requested = false

      se = self; @io.instance_eval { @my_selectable = se }
      Reactor.instance.add_selectable @io
    end

    def close_scheduled?
      @close_scheduled
    end

    def select_for_reading?
      false
    end

    def select_for_writing?
      false
    end

    def get_peername
      nil
    end

    def set_inactivity_timeout tm
      @inactivity_timeout = tm
    end

    def heartbeat
    end
  end

end

module EventMachine
  # @private
  class StreamObject < Selectable
    def initialize io
      super io
      @outbound_q = []
    end

    # If we have to close, or a close-after-writing has been requested,
    # then don't read any more data.
    def select_for_reading?
      true unless (@close_scheduled || @close_requested)
    end

    # If we have to close, don't select for writing.
    # Otherwise, see if the protocol is ready to close.
    # If not, see if he has data to send.
    # If a close-after-writing has been requested and the outbound queue
    # is empty, convert the status to close_scheduled.
    def select_for_writing?
      unless @close_scheduled
        if @outbound_q.empty?
          @close_scheduled = true if @close_requested
          false
        else
          true
        end
      end
    end

    # Proper nonblocking I/O was added to Ruby 1.8.4 in May 2006.
    # If we have it, then we can read multiple times safely to improve
    # performance.
    # The last-activity clock ASSUMES that we only come here when we
    # have selected readable.
    # TODO, coalesce multiple reads into a single event.
    # TODO, do the function check somewhere else and cache it.
    def eventable_read
      @last_activity = Reactor.instance.current_loop_time
      begin
        if io.respond_to?(:read_nonblock)
          10.times {
            data = io.read_nonblock(4096)
            EventMachine::event_callback uuid, ConnectionData, data
          }
        else
          data = io.sysread(4096)
          EventMachine::event_callback uuid, ConnectionData, data
        end
      rescue Errno::EAGAIN, Errno::EWOULDBLOCK
        # no-op
      rescue Errno::ECONNRESET, Errno::ECONNREFUSED, EOFError
        @close_scheduled = true
        EventMachine::event_callback uuid, ConnectionUnbound, nil
      end

    end

    # Provisional implementation. Will be re-implemented in subclasses.
    # TODO: Complete this implementation. As it stands, this only writes
    # a single packet per cycle. Highly inefficient, but required unless
    # we're running on a Ruby with proper nonblocking I/O (Ruby 1.8.4
    # built from sources from May 25, 2006 or newer).
    # We need to improve the loop so it writes multiple times, however
    # not more than a certain number of bytes per cycle, otherwise
    # one busy connection could hog output buffers and slow down other
    # connections. Also we should coalesce small writes.
    # URGENT TODO: Coalesce small writes. They are a performance killer.
    # The last-activity recorder ASSUMES we'll only come here if we've
    # selected writable.
    def eventable_write
      # coalesce the outbound array here, perhaps
      @last_activity = Reactor.instance.current_loop_time
      while data = @outbound_q.shift do
        begin
          data = data.to_s
          w = if io.respond_to?(:write_nonblock)
                io.write_nonblock data
              else
                io.syswrite data
              end

          if w < data.length
            @outbound_q.unshift data[w..-1]
            break
          end
        rescue Errno::EAGAIN
          @outbound_q.unshift data
        rescue EOFError, Errno::ECONNRESET, Errno::ECONNREFUSED
          @close_scheduled = true
          @outbound_q.clear
        end
      end

    end

    # #send_data
    def send_data data
      # TODO, coalesce here perhaps by being smarter about appending to @outbound_q.last?
      unless @close_scheduled or @close_requested or !data or data.length <= 0
        @outbound_q << data.to_s
      end
    end

    # #schedule_close
    # The application wants to close the connection.
    def schedule_close after_writing
      if after_writing
        @close_requested = true
      else
        @close_scheduled = true
      end
    end

    # #get_peername
    # This is defined in the normal way on connected stream objects.
    # Return an object that is suitable for passing to Socket#unpack_sockaddr_in or variants.
    # We could also use a convenience method that did the unpacking automatically.
    def get_peername
      io.getpeername
    end

    # #get_outbound_data_size
    def get_outbound_data_size
      @outbound_q.inject(0) {|memo,obj| memo += (obj || "").length}
    end

    def heartbeat
      if @inactivity_timeout and @inactivity_timeout > 0 and (@last_activity + @inactivity_timeout) < Reactor.instance.current_loop_time
        schedule_close true
      end
    end
  end


end


#--------------------------------------------------------------



module EventMachine
  # @private
  class EvmaTCPClient < StreamObject

    def self.connect bind_addr, bind_port, host, port
      sd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
      sd.bind( Socket.pack_sockaddr_in( bind_port, bind_addr ))  if bind_addr

      begin
        # TODO, this assumes a current Ruby snapshot.
        # We need to degrade to a nonblocking connect otherwise.
        sd.connect_nonblock( Socket.pack_sockaddr_in( port, host ))
      rescue Errno::EINPROGRESS
      end
      EvmaTCPClient.new sd
    end


    def initialize io
      super
      @pending = true
    end


    def select_for_writing?
      @pending ? true : super
    end

    def select_for_reading?
      @pending ? false : super
    end

    def eventable_write
      if @pending
        @pending = false
        if 0 == io.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).unpack("i").first
          EventMachine::event_callback uuid, ConnectionCompleted, ""
        end
      else
        super
      end
    end



  end
end



module EventMachine
  # @private
  class EvmaKeyboard < StreamObject

    def self.open
      EvmaKeyboard.new STDIN
    end


    def initialize io
      super
    end


    def select_for_writing?
      false
    end

    def select_for_reading?
      true
    end


  end
end



module EventMachine
  # @private
  class EvmaUNIXClient < StreamObject

    def self.connect chain
      sd = Socket.new( Socket::AF_LOCAL, Socket::SOCK_STREAM, 0 )
      begin
        # TODO, this assumes a current Ruby snapshot.
        # We need to degrade to a nonblocking connect otherwise.
        sd.connect_nonblock( Socket.pack_sockaddr_un( chain ))
      rescue Errno::EINPROGRESS
      end
      EvmaUNIXClient.new sd
    end


    def initialize io
      super
      @pending = true
    end


    def select_for_writing?
      @pending ? true : super
    end

    def select_for_reading?
      @pending ? false : super
    end

    def eventable_write
      if @pending
        @pending = false
        if 0 == io.getsockopt(Socket::SOL_SOCKET, Socket::SO_ERROR).unpack("i").first
          EventMachine::event_callback uuid, ConnectionCompleted, ""
        end
      else
        super
      end
    end



  end
end


#--------------------------------------------------------------

module EventMachine
  # @private
  class EvmaTCPServer < Selectable

    # TODO, refactor and unify with EvmaUNIXServer.

    class << self
      # Versions of ruby 1.8.4 later than May 26 2006 will work properly
      # with an object of type TCPServer. Prior versions won't so we
      # play it safe and just build a socket.
      #
      def start_server host, port
        sd = Socket.new( Socket::AF_INET, Socket::SOCK_STREAM, 0 )
        sd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true )
        sd.bind( Socket.pack_sockaddr_in( port, host ))
        sd.listen( 50 ) # 5 is what you see in all the books. Ain't enough.
        EvmaTCPServer.new sd
      end
    end

    def initialize io
      super io
    end


    def select_for_reading?
      true
    end

    #--
    # accept_nonblock returns an array consisting of the accepted
    # socket and a sockaddr_in which names the peer.
    # Don't accept more than 10 at a time.
    def eventable_read
      begin
        10.times {
          descriptor,peername = io.accept_nonblock
          sd = StreamObject.new descriptor
          EventMachine::event_callback uuid, ConnectionAccepted, sd.uuid
        }
      rescue Errno::EWOULDBLOCK, Errno::EAGAIN
      end
    end

    #--
    #
    def schedule_close
      @close_scheduled = true
    end

  end
end


#--------------------------------------------------------------

module EventMachine
  # @private
  class EvmaUNIXServer < Selectable

    # TODO, refactor and unify with EvmaTCPServer.

    class << self
      # Versions of ruby 1.8.4 later than May 26 2006 will work properly
      # with an object of type TCPServer. Prior versions won't so we
      # play it safe and just build a socket.
      #
      def start_server chain
        sd = Socket.new( Socket::AF_LOCAL, Socket::SOCK_STREAM, 0 )
        sd.setsockopt( Socket::SOL_SOCKET, Socket::SO_REUSEADDR, true )
        sd.bind( Socket.pack_sockaddr_un( chain ))
        sd.listen( 50 ) # 5 is what you see in all the books. Ain't enough.
        EvmaUNIXServer.new sd
      end
    end

    def initialize io
      super io
    end


    def select_for_reading?
      true
    end

    #--
    # accept_nonblock returns an array consisting of the accepted
    # socket and a sockaddr_in which names the peer.
    # Don't accept more than 10 at a time.
    def eventable_read
      begin
        10.times {
          descriptor,peername = io.accept_nonblock
          sd = StreamObject.new descriptor
          EventMachine::event_callback uuid, ConnectionAccepted, sd.uuid
        }
      rescue Errno::EWOULDBLOCK, Errno::EAGAIN
      end
    end

    #--
    #
    def schedule_close
      @close_scheduled = true
    end

  end
end



#--------------------------------------------------------------

module EventMachine
  # @private
  class LoopbreakReader < Selectable

    def select_for_reading?
      true
    end

    def eventable_read
      io.sysread(128)
      EventMachine::event_callback "", LoopbreakSignalled, ""
    end

  end
end



# @private
module EventMachine
  # @private
  class DatagramObject < Selectable
    def initialize io
      super io
      @outbound_q = []
    end

    # #send_datagram
    def send_datagram data, target
      # TODO, coalesce here perhaps by being smarter about appending to @outbound_q.last?
      unless @close_scheduled or @close_requested
        @outbound_q << [data.to_s, target]
      end
    end

    # #select_for_writing?
    def select_for_writing?
      unless @close_scheduled
        if @outbound_q.empty?
          @close_scheduled = true if @close_requested
          false
        else
          true
        end
      end
    end

    # #select_for_reading?
    def select_for_reading?
      true
    end

    # #get_outbound_data_size
    def get_outbound_data_size
      @outbound_q.inject(0) {|memo,obj| memo += (obj || "").length}
    end


  end


end


module EventMachine
  # @private
  class EvmaUDPSocket < DatagramObject

    class << self
      def create host, port
        sd = Socket.new( Socket::AF_INET, Socket::SOCK_DGRAM, 0 )
        sd.bind Socket::pack_sockaddr_in( port, host )
        EvmaUDPSocket.new sd
      end
    end

    # #eventable_write
    # This really belongs in DatagramObject, but there is some UDP-specific stuff.
    def eventable_write
      40.times {
        break if @outbound_q.empty?
        begin
          data,target = @outbound_q.first

          # This damn better be nonblocking.
          io.send data.to_s, 0, target

          @outbound_q.shift
        rescue Errno::EAGAIN
          # It's not been observed in testing that we ever get here.
          # True to the definition, packets will be accepted and quietly dropped
          # if the system is under pressure.
          break
        rescue EOFError, Errno::ECONNRESET
          @close_scheduled = true
          @outbound_q.clear
        end
      }
    end

    # Proper nonblocking I/O was added to Ruby 1.8.4 in May 2006.
    # If we have it, then we can read multiple times safely to improve
    # performance.
    def eventable_read
      begin
        if io.respond_to?(:recvfrom_nonblock)
          40.times {
            data,@return_address = io.recvfrom_nonblock(16384)
            EventMachine::event_callback uuid, ConnectionData, data
            @return_address = nil
          }
        else
          raise "unimplemented datagram-read operation on this Ruby"
        end
      rescue Errno::EAGAIN
        # no-op
      rescue Errno::ECONNRESET, EOFError
        @close_scheduled = true
        EventMachine::event_callback uuid, ConnectionUnbound, nil
      end

    end


    def send_data data
      send_datagram data, @return_address
    end

  end
end

# load base EM api on top, now that we have the underlying pure ruby
# implementation defined
require 'eventmachine'

