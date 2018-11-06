# --
# Copyright 2015 Verisign
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require 'rubydns'
require 'nio'
require 'socket'
require 'thread'

class SimpleTimers
  def initialize
    @events = {}
  end

  def empty?
    @events.empty?
  end

  def after(seconds, &block)
    eventTime = Time.now + seconds
    @events[eventTime] ||= []
    @events[eventTime] << block
  end

  def fire
    now = Time.now

    events = @events.select { |key, value| key <= now }

    (events || []).each do |key, blocks|
      blocks.each do |block|
        block.call
      end
      @events.delete(key)
    end
  end

  def wait_interval
    next_event = @events.keys.min
    next_event.nil? ? nil : next_event - Time.now
  end
end

# NioTcpPipeliningHandler accepts new tcp connection and reads data from the sockets until
# either the client closes the connection, @max_requests_per_connection is reached
# or @timeout is attained.

class NioTcpPipeliningHandler < RubyDNS::GenericHandler

  DEFAULT_MAX_REQUESTS = 4
  DEFAULT_TIMEOUT = 3
  # TODO Add timeout
  def initialize(server, host, port, max_requests = DEFAULT_MAX_REQUESTS, timeout = DEFAULT_TIMEOUT)
    super(server)
    @max_requests_per_connection = max_requests
    @timeout = timeout
    @socket = TCPServer.new(host, port)
    @count = {}

    @server.class.stats.connections = @count.keys.count

    @timers = SimpleTimers.new

    @selector = NIO::Selector.new
    monitor = @selector.register(@socket, :r)
    monitor.value = proc { accept }

    async.run
  end

  finalizer :finalize

  def finalize
    @socket.close if @socket
    @selector.close
    @selector_thread.join
  end

  def run
    @logger.debug "Running selector thread"
    @selector_thread = create_selector_thread
  end

  def accept
    handle_connection(@socket.accept)
  end

  def process_socket(socket)
    @logger.debug "Processing socket"
    _, _remote_port, remote_host = socket.peeraddr
    options = { peer: remote_host }

    new_connection = @count[socket].nil?
    @count[socket] ||= 0
    @count[socket]  += 1
    @server.class.stats.connection_accept(new_connection, @count.keys.count)

    #we read all data until timeout
    input_data = RubyDNS::StreamTransport.read_chunk(socket)

    if @count[socket] <= @max_requests_per_connection
      response = process_query(input_data, options)
      RubyDNS::StreamTransport.write_message(socket, response)
    end

=begin
    if @count[socket] >= @max_requests_per_connection
      _, port, host = socket.peeraddr
      @logger.debug("*** max request for #{host}:#{port}")
      remove(socket)
    end
=end
  rescue EOFError
    _, port, host = socket.peeraddr
    @logger.debug("*** #{host}:#{port} disconnected")

    remove(socket)
  end

  def remove(socket, update_connections=true)
    @logger.debug("Removing socket from selector")
    socket.close rescue nil
    @selector.deregister(socket) rescue nil
    socket_count = @count.delete(socket)
    @server.class.stats.connections = @count.keys.count if update_connections
    socket_count
  end

  def create_selector_thread
    Thread.new do
      loop do
        begin
          @timers.fire
          intervals = [@timers.wait_interval || 0.1, 0.1]

          @selector.select(intervals.min > 0 ? intervals.min : 0.1) do
            |monitor| monitor.value.call(monitor)
          end

          @logger.debug "Woke up"
          break if @selector.closed?
        rescue Exception => e
          @logger.debug "Exception #{e}"
          @logger.debug "Backtrace #{e.backtrace}"
        end
      end
    end
  end

  def handle_connection(socket)
    @logger.debug "New connection"
    @logger.debug "Add socket to @selector"

    monitor = @selector.register(socket, :r)
    monitor.value = proc { process_socket(socket) }

    @logger.debug "Add socket timer of #{@timeout}"
    @timers.after(@timeout) do
      @logger.debug "Timeout fired for socket #{socket}"
      count = remove(socket, false)
      unless count.nil?
        @logger.debug "Timeout for socket #{socket}"
        @logger.debug "Increasing timeout count"
        @server.class.stats.connection_timeout(@count.keys.count)
      end
    end
  end
end

# Stats collects statistics from our tcp handler
class Stats
  def initialize()
    @mutex         = Mutex.new
    @accept_count  = 0
    @timeout_count = 0
    @max_count     = 0
    @connections   = 0
  end

  def increment_max;        @mutex.synchronize { @max_count     += 1 } end
  def increment_timeout;    @mutex.synchronize { @timeout_count += 1 } end
  def increment_connection; @mutex.synchronize { @accept_count  += 1 } end

  def connection_timeout(active_connections)
    @mutex.synchronize do
      @timeout_count += 1
      @connections = active_connections
    end
  end

  def connection_accept(new_connection, active_connections)
    @mutex.synchronize {
      @connections    = active_connections
      @accept_count  += 1 if new_connection
    }
  end

  def connections=(active_connections)
    @mutex.synchronize { @connections = active_connections }
  end

  def connections
    @mutex.synchronize { @connections }
  end

  def accept_count
    @mutex.synchronize { @accept_count  }
  end

  def timeout_count
    @mutex.synchronize { @timeout_count }
  end

  def max_count
    @mutex.synchronize { @max_count }
  end
end
