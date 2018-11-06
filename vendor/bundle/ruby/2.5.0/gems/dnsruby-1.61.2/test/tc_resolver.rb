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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either tmexpress or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++
require_relative 'spec_helper'

require 'socket'

# @TODO@ We also need a test server so we can control behaviour of server to test
# different aspects of retry strategy.
# Of course, with Ruby's limit of 256 open sockets per process, we'd need to run
# the server in a different Ruby process.

class TestResolver < Minitest::Test

  include Dnsruby

  Thread::abort_on_exception = true

  GOOD_DOMAIN_NAME = 'example.com'
  BAD_DOMAIN_NAME  = 'dnsruby-test-of-bad-domain-name.blah'

  PORT = 42138
  @@port = PORT

  def setup
    Dnsruby::Config.reset
  end

  def assert_valid_response(response)
    assert(response.kind_of?(Message), "Expected response to be a message but was a #{response.class}")
  end

  def assert_nil_response(response)
    assert(response.nil?, "Expected no response but got a #{response.class}:\n#{response}")
  end

  def assert_error_is_exception(error, error_class = Exception)
    assert(error.is_a?(error_class), "Expected error to be an #{error_class}, but was a #{error.class}:\n#{error}")
  end

  def assert_nil_error(error)
    assert(error.nil?, "Expected no error but got a #{error.class}:\n#{error}")
  end

  def test_send_message
    response = Resolver.new.send_message(Message.new("example.com", Types.A))
    assert_valid_response(response)
  end

  def test_send_message_bang_noerror
    response, error = Resolver.new.send_message!(Message.new(GOOD_DOMAIN_NAME, Types.A))
    assert_nil_error(error)
    assert_valid_response(response)
  end

  def test_send_message_bang_error
    message = Message.new(BAD_DOMAIN_NAME, Types.A)
    response, error = Resolver.new.send_message!(message)
    assert_nil_response(response)
    assert_error_is_exception(error)
  end

  def test_send_plain_message
    resolver = Resolver.new
    response, error = resolver.send_plain_message(Message.new("cnn.com"))
    assert_nil_error(error)
    assert_valid_response(response)

    m = Message.new(BAD_DOMAIN_NAME)
    m.header.rd = true
    response, error = resolver.send_plain_message(m)
    assert_valid_response(response)
    assert_error_is_exception(error, NXDomain)
  end

  def test_query
    response = Resolver.new.query("example.com")
    assert_valid_response(response)
  end

  def test_query_bang_noerror
    response, error = Resolver.new.query!(GOOD_DOMAIN_NAME)
    assert_nil_error(error)
    assert_valid_response(response)
  end

  def test_query_bang_error
    response, error = Resolver.new.query!(BAD_DOMAIN_NAME)
    assert_nil_response(response)
    assert_error_is_exception(error)
  end

  def test_query_async
    q = Queue.new
    Resolver.new.send_async(Message.new("example.com", Types.A),q,q)
    id, response, error = q.pop
    assert_equal(id, q, "Id wrong!")
    assert_valid_response(response)
    assert_nil_error(error)
  end

  def test_query_one_duff_server_one_good
    res = Resolver.new({:nameserver => ["8.8.8.8", "8.8.8.7"]})
    res.retry_delay=1
    q = Queue.new
    res.send_async(Message.new("example.com", Types.A),q,q)
    id, response, error = q.pop
    assert_equal(id, q, "Id wrong!")
    assert_valid_response(response)
    assert_nil_error(error)
  end

  #  @TODO@ Implement!!  But then, why would anyone want to do this?
  #   def test_many_threaded_clients
  #     assert(false, "IMPLEMENT!")
  #   end

  def test_reverse_lookup
    m = Message.new("8.8.8.8", Types.PTR)
    r = Resolver.new
    q=Queue.new
    r.send_async(m,q,q)
    id,ret, error=q.pop
    assert(ret.kind_of?(Message))
    no_pointer=true
    ret.each_answer do |answer|
      if (answer.type==Types.PTR)
        no_pointer=false
        assert(answer.domainname.to_s=~/google-public-dns/)
      end
    end
    assert(!no_pointer)
  end

#  def test_bad_host
#    res = Resolver.new({:nameserver => "localhost"})
#    res.retry_times=1
#    res.retry_delay=0
#    res.query_timeout = 1
#    q = Queue.new
#    res.send_async(Message.new("example.com", Types.A), q, q)
#    id, m, err = q.pop
#    assert(id==q)
#    assert(m == nil)
#    assert(err.kind_of?(OtherResolvError) || err.kind_of?(IOError), "OtherResolvError or IOError expected : got #{err.class}")
#  end
#
  def test_nxdomain
    resolver = Resolver.new
    q = Queue.new
    resolver .send_async(Message.new(BAD_DOMAIN_NAME, Types.A), q, 1)
    id, m, error = q.pop
    assert(id==1, "Id should have been 1 but was #{id}")
    assert(m.rcode == RCode.NXDOMAIN, "Expected NXDOMAIN but got #{m.rcode} instead.")
    assert_error_is_exception(error, NXDomain)
  end

  def test_timeouts
    # test timeout behaviour for different retry, retrans, total timeout etc.
    # Problem here is that many sockets will be created for queries which time out.
    #  Run a query which will not respond, and check that the timeout works
    if (!RUBY_PLATFORM=~/darwin/)
      start=stop=0
      retry_times = 3
      retry_delay=1
      packet_timeout=2
      #  Work out what time should be, then time it to check
      expected = ((2**(retry_times-1))*retry_delay) + packet_timeout
      begin
        res = Dnsruby::Resolver.new({:nameserver => "10.0.1.128"})
        #       res = Resolver.new({:nameserver => "213.248.199.17"})
        res.packet_timeout=packet_timeout
        res.retry_times=retry_times
        res.retry_delay=retry_delay
        start=Time.now
        m = res.send_message(Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk", Types.A))
        fail
      rescue ResolvTimeout
        stop=Time.now
        time = stop-start
        assert(time <= expected * 1.3 && time >= expected * 0.9, "Wrong time take, expected #{expected}, took #{time}")
      end
  end
  end

  def test_packet_timeout
        res = Dnsruby::Resolver.new({:nameserver => []})
#      res = Resolver.new({:nameserver => "10.0.1.128"})
      start=stop=0
      retry_times = retry_delay = packet_timeout= 10
      query_timeout=2
      begin
        res.packet_timeout=packet_timeout
        res.retry_times=retry_times
        res.retry_delay=retry_delay
        res.query_timeout=query_timeout
        #  Work out what time should be, then time it to check
        expected = query_timeout
        start=Time.now
        m = res.send_message(Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk", Types.A))
        fail
      rescue Dnsruby::ResolvTimeout
        stop=Time.now
        time = stop-start
        assert(time <= expected * 1.3 && time >= expected * 0.9, "Wrong time take, expected #{expected}, took #{time}")
      end    #
  end

  def test_queue_packet_timeout
#    if (!RUBY_PLATFORM=~/darwin/)
      res = Dnsruby::Resolver.new({:nameserver => "10.0.1.128"})
#      bad = SingleResolver.new("localhost")
      res.add_server("localhost")
      expected = 2
      res.query_timeout=expected
      q = Queue.new
      start = Time.now
      m = res.send_async(Message.new("a.t.dnsruby.validation-test-servers.nominet.org.uk", Types.A), q, q)
      id,ret,err = q.pop
      stop = Time.now
      assert(id=q)
      assert(ret==nil)
      assert(err.class == ResolvTimeout, "#{err.class}, #{err}")
      time = stop-start
      assert(time <= expected * 1.3 && time >= expected * 0.9, "Wrong time take, expected #{expected}, took #{time}")
#    end
  end

  def test_illegal_src_port
    #  Also test all singleresolver ports ok
    #  Try to set src_port to an illegal value - make sure error raised, and port OK
    res = Dnsruby::Resolver.new
    res.port = 56789
    tests = [53, 387, 1265, 3210, 48619]
    tests.each do |bad_port|
      begin
        res.src_port = bad_port
        fail("bad port #{bad_port}")
      rescue
      end
    end
    assert(res.single_resolvers[0].src_port = 56789)
  end

  def test_add_src_port
    #  Try setting and adding port ranges, and invalid ports, and 0.
    #  Also test all singleresolver ports ok
    res = Resolver.new
    res.src_port = [56789,56790, 56793]
    assert(res.src_port == [56789,56790, 56793])
    res.src_port = 56889..56891
    assert(res.src_port == [56889,56890,56891])
    res.add_src_port(60000..60002)
    assert(res.src_port == [56889,56890,56891,60000,60001,60002])
    res.add_src_port([60004,60005])
    assert(res.src_port == [56889,56890,56891,60000,60001,60002,60004,60005])
    res.add_src_port(60006)
    assert(res.src_port == [56889,56890,56891,60000,60001,60002,60004,60005,60006])
    #  Now test invalid src_ports
    tests = [0, 53, [60007, 53], [60008, 0], 55..100]
    tests.each do |x|
      begin
        res.add_src_port(x)
        fail()
      rescue
      end
    end
    assert(res.src_port == [56889,56890,56891,60000,60001,60002,60004,60005,60006])
    assert(res.single_resolvers[0].src_port == [56889,56890,56891,60000,60001,60002,60004,60005,60006])
  end

  def test_eventtype_api
    #  @TODO@ TEST THE Resolver::EventType interface!
  end
end


# Tests to see that query_raw handles send_plain_message's return values correctly.
class TestRawQuery < Minitest::Test

  KEY_NAME = 'key-name'
  KEY  = '0123456789'
  ALGO = 'hmac-md5'

  class CustomError < RuntimeError; end

  # Returns a new resolver whose send_plain_message method always returns
  # nil for the response, and a RuntimeError for the error.
  def resolver_returning_error
    resolver = Dnsruby::Resolver.new
    def resolver.send_plain_message(_message)
      [nil, CustomError.new]
    end
    resolver
  end

  # Returns a new resolver whose send_plain_message is overridden to return
  # :response_from_send_plain_message instead of a real Dnsruby::Message,
  # for easy comparison in the tests.
  def resolver_returning_response
    resolver = Dnsruby::Resolver.new
    def resolver.send_plain_message(_message)
      [:response_from_send_plain_message, nil]
    end
    resolver
  end

  # Test that when a strategy other than :raise or :return is passed,
  # an ArgumentError is raised.
  def test_bad_strategy
    assert_raises(ArgumentError) do
      resolver_returning_error.query_raw(Dnsruby::Message.new, :invalid_strategy)
    end
  end

  # Test that when send_plain_message returns an error,
  # and the error strategy is :raise, query_raw raises an error.
  def test_raise_error
    assert_raises(CustomError) do
      resolver_returning_error.query_raw(Dnsruby::Message.new, :raise)
    end
  end

  # Tests that if you don't specify an error strategy, an error will be
  # returned rather than raised (i.e. strategy defaults to :return).
  def test_return_error_is_default
    _response, error = resolver_returning_error.query_raw(Dnsruby::Message.new)
    assert error.is_a?(CustomError)
  end

  # Tests that when no error is returned, no error is raised.
  def test_raise_no_error
    response, _error = resolver_returning_response.query_raw(Dnsruby::Message.new, :raise)
    assert_equal :response_from_send_plain_message, response
  end

  # Test that when send_plain_message returns an error, and the error strategy
  # is set to :return, then an error is returned.
  def test_return_error
    _response, error = resolver_returning_error.query_raw(Dnsruby::Message.new, :return)
    assert error.is_a?(CustomError)
  end

  # Test that when send_plain_message returns a valid and response
  # and nil error, the same are returned by query_raw.
  def test_return_no_error
    response, error = resolver_returning_response.query_raw(Dnsruby::Message.new, :return)
    assert_nil error
    assert_equal :response_from_send_plain_message, response
  end

  def test_2_args_init
    options = Dnsruby::Resolver.create_tsig_options(KEY_NAME, KEY)
    assert_equal KEY_NAME, options[:name]
    assert_equal KEY, options[:key]
    assert_nil options[:algorithm]
  end

  def test_3_args_init
    options = Dnsruby::Resolver.create_tsig_options(KEY_NAME,KEY,ALGO)
    assert_equal KEY_NAME, options[:name]
    assert_equal KEY, options[:key]
    assert_equal ALGO, options[:algorithm]
  end
  
  def test_threads
    resolver = Dnsruby::Resolver.new(nameserver: ["8.8.8.8", "8.8.4.4"])
        resolver.query("google.com", "MX")
         resolver.query("google.com", "MX")
          resolver.query("google.com", "MX")
          begin
            resolver.query("googlöe.com", "MX") 
          rescue Dnsruby::ResolvError => e
            # fine
          end
          resolver.query("google.com", "MX")
          resolver.query("google.com", "MX")
          begin
            resolver.query("googlöe.com", "MX")
          rescue Dnsruby::ResolvError => e
            # fine
          end
          begin
            resolver.query("googlöe.com", "MX") 
          rescue Dnsruby::ResolvError => e
            # fine
          end
#          Dnsruby::Cache.delete("googlöe.com", "MX")
          
  end
end

