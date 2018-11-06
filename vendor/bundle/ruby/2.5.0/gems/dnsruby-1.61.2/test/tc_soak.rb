# --
# Copyright 2007 Nominet UK
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

# require_relative 'tc_single_resolver'
require_relative 'tc_soak_base'
require_relative 'test_dnsserver'


# This class tries to soak test the Dnsruby library.
# It can't do this very well, owing to the small number of sockets allowed to be open simultaneously.
# @TODO@ Future versions of dnsruby will allow random streaming over a fixed number of (cycling) random sockets,
# so this test can be beefed up considerably at that point.
# @todo@ A test DNS server running on localhost is really needed here

class MyServer < RubyDNS::Server

  include Dnsruby

  IP   = "127.0.0.1"
  PORT = 53927

  @@stats = Stats.new

  def self.stats
    @@stats
  end

  def process(name, resource_class, transaction)
    transaction.respond!("93.184.216.34", { resource_class: Resolv::DNS::Resource::IN::A })
    Celluloid.logger.debug "got message"
  end
end

class PipeliningServer < MyServer
  def run
    fire(:setup)

    link NioTcpPipeliningHandler.new(self, IP, PORT, 5) #5 max request
    link RubyDNS::UDPHandler.new(self, IP, PORT)

    fire(:start)
  end
end

class TestSingleResolverSoak < Minitest::Test

  IP   = MyServer::IP
  PORT = MyServer::PORT

  def initialize(arg)
    super(arg)
    self.class.init
  end

  def self.init
    unless @initialized
      Celluloid.boot
      # By default, Celluloid logs output to console. Use Dnsruby.log instead.
      Celluloid.logger = Dnsruby.log
      @initialized = true
    end
  end

  def teardown
    Celluloid.shutdown
  end

  SINGLE_RESOLVER_QUERY_TIMES = 63

  def setup
    # Instantiate a new server
    # For each query respond with 93.184.216.34

    @@supervisor ||= RubyDNS::run_server(asynchronous: true,
                                         server_class: PipeliningServer)

  end

  def test_many_asynchronous_queries_one_single_resolver
    run_many_asynch_queries_test_single_res(1)
  end

  def test_many_asynchronous_queries_many_single_resolvers
    run_many_asynch_queries_test_single_res(50)
  end

  def test_many_asynchronous_queries_one_single_resolver_tcp
    run_many_asynch_queries_test_single_res(1, true)
  end

  def test_many_asynchronous_queries_many_single_resolvers_tcp
    run_many_asynch_queries_test_single_res(50, true)
  end

  def test_many_asynchronous_queries_one_single_resolver_tcp_pipelining
    run_many_asynch_queries_test_single_res(1, true, true)
  end

  def test_many_asynchronous_queries_many_single_resolvers_tcp_pipelining
    run_many_asynch_queries_test_single_res(50, true, true)
  end

  def run_many_asynch_queries_test_single_res(num_resolvers, tcp = false, pipelining = false)
    q = Queue.new
    timeout_count = 0
    resolvers = Array.new(num_resolvers) do
      SingleResolver.new(server:                     IP,
                         port:                       PORT,
                         do_caching:                 false,
                         do_validation:              false,
                         tcp_pipelining:             pipelining,
                         packet_timeout:             10,
                         tcp_pipelining_max_queries: 5,
                         use_tcp:                    tcp)
    end
    start = Time.now

    #  @todo@ On windows, MAX_FILES is 256. This means that we have to limit
    #  this test while we're not using single sockets.
    #  We run four queries per iteration, so we're limited to 64 runs.
    messages = TestSoakBase::Rrs.map do |data|
      message = Message.new(data[:name], data[:type])
      message.do_validation = false
      message.do_caching    = false
      message
    end

    query_count = SINGLE_RESOLVER_QUERY_TIMES * messages.count

    receive_thread = Thread.new do
      query_count.times do
        _id, ret, error = q.pop
        if error.is_a?(ResolvTimeout)
          timeout_count+=1
        elsif ret.class != Message
          p "ERROR RETURNED : #{error}"
        end
      end
    end

    resolver_cycler = resolvers.cycle

    SINGLE_RESOLVER_QUERY_TIMES.times do |i|
      rr_count = 0
      messages.each do | message |
        rr_count += 1
        resolver_cycler.next.send_async(message, q, rr_count + i * messages.count)
        #         p "Sent #{i}, #{rr_count}, Queue #{q}"
      end
    end

    receive_thread.join

    time_taken = Time.now - start
    puts "Query count : #{query_count}, #{timeout_count} timed out. #{time_taken} time taken"
    assert(timeout_count < query_count * 0.1, "#{timeout_count} of #{query_count} timed out!")
  end

  def test_many_threads_on_one_single_resolver_synchronous
    #  Test multi-threaded behaviour
    #  Check the header IDs to make sure they're all different
    threads = Array.new

    res = create_default_single_resolver
    ids = []
    mutex = Mutex.new
    timeout_count = 0
    query_count = 0
    res.packet_timeout=4
    start=Time.now
    #  Windows limits us to 256 sockets
    num_times=250
    if (/java/ =~ RUBY_PLATFORM)
      #  JRuby threads are native threads, so let's not go too mad!
      num_times=50
    end
    num_times.times do |i|
      threads[i] = Thread.new{
        40.times do |j|
          TestSoakBase::Rrs.each do |data|
            mutex.synchronize { query_count += 1 }
            packet=nil
            begin
              packet = res.query(data[:name], data[:type])
            rescue ResolvTimeout
              mutex.synchronize { timeout_count += 1 }
              next
            end
            assert(packet)
            ids.push(packet.header.id)
            assert_equal(packet.question[0].qclass,    'IN',             'Class correct'           )
          end
        end
      }
    end
    threads.each do |thread|
      thread.join
    end
    stop=Time.now
    time_taken=stop-start
    puts "Query count : #{query_count}, #{timeout_count} timed out. #{time_taken} time taken"
    #     check_ids(ids) # only do this if we expect all different IDs - e.g. if we stream over a single socket
    assert(timeout_count < query_count * 0.1, "#{timeout_count} of #{query_count} timed out!")
  end

  def check_ids(ids)
    ids.sort!
    count = 0
    ids.each do |id|
      count+=1
      if (count < ids.length-1)
        assert(ids[count+1] != id, "Two identical header ids used!")
      end
    end
  end

  def test_many_threads_on_many_single_resolvers
    #  Test multi-threaded behaviour
    #  @todo@ Check the header IDs to make sure they're all different
    threads = Array.new
    mutex = Mutex.new
    timeout_count = 0
    query_count = 0
    start=Time.now
    num_times=250
    if (/java/ =~ RUBY_PLATFORM)
      #  JRuby threads are native threads, so let's not go too mad!
      num_times=50
    end
    num_times.times do |i|
      threads[i] = Thread.new{
        res = create_default_single_resolver
        40.times do |j|
          TestSoakBase::Rrs.each do |data|
            mutex.synchronize do
              query_count+=1
            end
            q = Queue.new

            message = Message.new(data[:name], data[:type])
            message.do_validation = false
            message.do_caching    = false

            res.send_async(message, q, [i,j])

            id, packet, error = q.pop
            if (error.class == ResolvTimeout)
              mutex.synchronize {
                timeout_count+=1
              }
              next
            elsif (packet.class!=Message)
              puts "ERROR! #{error}"
            end

            assert(packet)
            assert_equal(packet.question[0].qclass,    'IN',             'Class correct'           )
          end
        end
      }
    end
    # NOTE: For methods on the objects taking no params, we can use this shorthand.
    threads.each(&:join)

    time_taken = Time.now - start
    puts "Query count : #{query_count}, #{timeout_count} timed out. #{time_taken} time taken"
    assert(timeout_count < query_count * 0.1, "#{timeout_count} of #{query_count} timed out!")
  end


  def create_default_single_resolver
    SingleResolver.new(server:         IP,
                       port:           PORT,
                       do_caching:     false,
                       do_validation:  false,
                       packet_timeout: 10)

  end
end
