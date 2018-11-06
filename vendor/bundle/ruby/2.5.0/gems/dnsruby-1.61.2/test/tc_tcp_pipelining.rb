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

require_relative 'spec_helper'
require_relative 'test_dnsserver'

# The TCPPipeliningServer links our NioTcpPipeliningHandler on
# the loopback interface.
class TCPPipeliningServer < RubyDNS::Server
  PORT     = 53937
  IP   = '127.0.0.1'

  DEFAULT_MAX_REQUESTS = 4
  DEFAULT_TIMEOUT = 3

  @@stats = Stats.new

  def self.stats
    @@stats
  end

  def process(name, resource_class, transaction)
    @logger.debug "name: #{name}"
    transaction.respond!("93.184.216.34", { resource_class: Resolv::DNS::Resource::IN::A })
  end

  def run
    fire(:setup)

    link NioTcpPipeliningHandler.new(self, IP, PORT, DEFAULT_MAX_REQUESTS, DEFAULT_TIMEOUT) #4 max request

    fire(:start)
  end
end

class TestTCPPipelining < Minitest::Test

  class << self
    attr_accessor :query_id
  end

  def self.init
    unless @initialized
      Celluloid.boot
      # By default, Celluloid logs output to console. Use Dnsruby.log instead
      Celluloid.logger = Dnsruby.log
      #Dnsruby.log.level = Logger::ERROR
      @initialized = true
      @query_id = 0
    end
  end

  def teardown
    if @initialized
      Celluloid.shutdown
      @initialized = false
    end
  end

  def setup
    self.class.init

    # Instantiate a new server that uses our tcp pipelining handler
    # For each query the server sends the query upstream (193.0.14.129)
    options = {
        server_class: TCPPipeliningServer,
        asynchronous: true
    }

    @@supervisor ||= RubyDNS::run_server(options)

    # Instantiate our resolver. The resolver will use the same pipeline as much as possible.
    # If a timeout occurs or max_request_per_connection a new connection should be initiated
    @@resolver ||= Dnsruby::Resolver.new(
        use_tcp:                    true,
        do_caching:                 false,
        tcp_pipelining:             true,
        dnssec:                     false,
        packet_timeout:             10,
        tcp_pipelining_max_queries: 10,
        nameserver:                 TCPPipeliningServer::IP,
        port:                       TCPPipeliningServer::PORT)
  end

  # Send x number of queries asynchronously to our resolver
  def send_async_messages(number_of_messages, queue, wait_seconds = 0)
    Celluloid.logger.debug "Sending #{number_of_messages} messages"
    number_of_messages.times do
      name = "#{self.class.query_id}.com"
      Celluloid.logger.debug "Sending #{name}"
      message = Dnsruby::Message.new(name)
      # self.class.query_id identifies our query, must be different for each message
      @@resolver.send_async(message, queue, self.class.query_id)
      self.class.query_id += 1

      # Note: For 0, we don't sleep at all instead of sleeping 0 since sleeping 0
      # involves yielding the CPU.
      sleep wait_seconds unless wait_seconds == 0
    end
  end

  # Verify x responses with no exception
  def verify_responses(number_of_messages, queue)
    number_of_messages.times do
      _response_id, response, exception = queue.pop
      assert_nil(exception)
      assert(response.is_a?(Dnsruby::Message))
    end
  end

  def accept_wait(accept_count, max)
    i = 0
    while TCPPipeliningServer.stats.accept_count < accept_count
      sleep 0.5
      i+=0.5
      assert(i<max, "Max wait for accept reached #{TCPPipeliningServer.stats.accept_count} accepts < #{accept_count}")
    end
  end

  def connection_wait(connection_count, max)
    i = 0
    while TCPPipeliningServer.stats.connections > connection_count
      sleep 0.5
      i+=0.5
      assert(i<max, "Max wait for connection reached: #{TCPPipeliningServer.stats.connections} active connections > #{connection_count}")
    end
  end

  def timeout_wait(timeout_count, max)
    i = 0
    while TCPPipeliningServer.stats.timeout_count < timeout_count
      sleep 0.5
      i+=0.5
      assert(i<max, "Max wait for timeout reached #{TCPPipeliningServer.stats.timeout_count} timeounts < #{timeout_count}")
    end
  end

  # This test initiates multiple asynchronous requests and verifies they go on the same tcp
  # pipeline or a new one depending on timeouts
  def test_TCP_pipelining_timeout
    Celluloid.logger.debug "test_TCP_pipelining_timeout"
    connection_wait(0, TCPPipeliningServer::DEFAULT_TIMEOUT*5)

    accept_count  = TCPPipeliningServer.stats.accept_count
    timeout_count = TCPPipeliningServer.stats.timeout_count

    # This is the main queue used to communicate between Dnsruby in async mode and the client
    query_queue = Queue.new

    # Test basic pipelining. All request should go on the same tcp connection.
    # TCPPipeliningServer.stats.accept_count should be 1.
    send_async_messages(3, query_queue)
    verify_responses(3, query_queue)

    assert_equal(accept_count + 1, TCPPipeliningServer.stats.accept_count)

    connection_wait(0, TCPPipeliningServer::DEFAULT_TIMEOUT*5)
    timeout_wait(timeout_count + 1, TCPPipeliningServer::DEFAULT_TIMEOUT*5)

    assert_equal(timeout_count + 1, TCPPipeliningServer.stats.timeout_count)

    # Initiate another 3 queries, check accept_count and timeout_count
    send_async_messages(3, query_queue)
    verify_responses(3, query_queue)

    connection_wait(0, TCPPipeliningServer::DEFAULT_TIMEOUT*5)
    timeout_wait(timeout_count + 2, TCPPipeliningServer::DEFAULT_TIMEOUT*5)

    assert_equal(accept_count + 2, TCPPipeliningServer.stats.accept_count)
    assert_equal(timeout_count + 2, TCPPipeliningServer.stats.timeout_count)

    connection_wait(0, TCPPipeliningServer::DEFAULT_TIMEOUT*5)
  end

  # Test timeout occurs and new connection is initiated inbetween 2 sends
  def test_TCP_pipelining_timeout_in_send
    Celluloid.logger.debug "test_TCP_pipelining_timeout_in_send"
    connection_wait(0, TCPPipeliningServer::DEFAULT_TIMEOUT*5)

    accept_count  = TCPPipeliningServer.stats.accept_count
    timeout_count = TCPPipeliningServer.stats.timeout_count

    query_queue = Queue.new

    # Initiate another 2 queries wait and then send a final query
    # Check accept_count. Wait for timeout and verify we got 2 additional timeouts.
    send_async_messages(2, query_queue)
    verify_responses(2, query_queue)

    accept_wait(accept_count+1, TCPPipeliningServer::DEFAULT_TIMEOUT*5)
    connection_wait(0, TCPPipeliningServer::DEFAULT_TIMEOUT*5)

    send_async_messages(1, query_queue)

    verify_responses(1, query_queue)

    assert_equal(accept_count + 2, TCPPipeliningServer.stats.accept_count)

    connection_wait(0, TCPPipeliningServer::DEFAULT_TIMEOUT*5)

    timeout_wait(timeout_count + 2, TCPPipeliningServer::DEFAULT_TIMEOUT*5)
  end

  # Test that we get a SocketEofResolvError if the servers closes the socket before
  # all queries are answered
  def test_TCP_pipelining_socket_eof
    connection_wait(0, TCPPipeliningServer::DEFAULT_TIMEOUT*5)

    query_queue = Queue.new

    # Issue 6 queries. Only 4 should be replied since max_request_per_connection = 4
    # Verify we get Dnsruby::SocketEofResolvError on the last 2.
    # Verify we got max_count was incremented
    send_async_messages(6, query_queue)

    responses = []

    6.times do
      response = query_queue.pop
      responses << response
    end

    responses.sort_by { |response| response[0] }

    step = 0

    responses.each do | response |
      _response_id, response, exception = response
      if step < TCPPipeliningServer::DEFAULT_MAX_REQUESTS
        assert_nil(exception, "Exception not nil for msg #{step} < #{TCPPipeliningServer::DEFAULT_MAX_REQUESTS} requests")
        assert(response.is_a?(Dnsruby::Message))
      else
        assert_equal(Dnsruby::SocketEofResolvError, exception.class)
        assert_nil(response)
      end
      step += 1
    end

    connection_wait(0, TCPPipeliningServer::DEFAULT_TIMEOUT*5)
  end
end
