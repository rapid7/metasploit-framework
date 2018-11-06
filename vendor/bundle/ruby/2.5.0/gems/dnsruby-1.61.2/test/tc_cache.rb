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

class TestCache < Minitest::Test

  include Dnsruby

  def test_cache
    cache = Cache.new
    m1 = Message.new("example.com.", Types.A, Classes.IN)
    rr1 = RR.create("example.com.		3	IN	A	208.77.188.166")
    m1.add_answer(rr1)
    m1.header.aa = true
    assert(!m1.cached)
    cache.add(m1)
    ret = cache.find("example.com", "A")
    assert(ret.cached)
    assert(ret.answer.rrset("example.com", "A").to_s == m1.answer.rrset("example.com", "A").to_s, "#{m1.answer.rrset("example.com", "A").to_s}end\n#{ret.answer.rrset("example.com", "A").to_s}end" )
    assert(ret.header.aa == false)
    assert(ret.answer.rrsets()[0].ttl == 3)
    sleep(1)
    ret = cache.find("example.com", "A")
    assert(ret.cached)
    assert((ret.answer.rrsets()[0].ttl == 2) || (ret.answer.rrsets()[0].ttl == 1), "ttl = #{ret.answer.rrsets()[0].ttl}")
    assert(ret.answer != m1.answer, "ret.answer=#{ret.answer}\nm1.answer=#{m1.answer}" )
    assert(ret.header.aa == false)
    sleep(2) # TTL of 3 should have timed out now
    ret = cache.find("example.com", "A")
    assert(!ret)
    cache.add(m1)
    m2 = Message.new("example.com.", Types.A, Classes.IN)
    rr2 = RR.create("example.com.		200	IN	A	208.77.188.166")
    m2.add_answer(rr2)
    m2.header.aa = true
    cache.add(m2)
    ret = cache.find("example.com", "A")
    assert(ret.cached)
    assert(ret.answer.rrsets()[0].ttl == 200)
  end

  def test_opt_record
    #  Create a very large message, encode it and decode it - there should be an opt record
    #  test getting that in and out the cache
    #  We should be able to do this in the online test by getting back a very big
    #  record from the test zone
  end

  def test_negative

  end

  def test_cache_max_size
    Dnsruby::Cache.max_size=1
    res = Resolver.new()
    Dnsruby::PacketSender.clear_caches()
    assert(Dnsruby::PacketSender.recursive_cache_length == 0)
    msg = res.query("example.com")
    assert(!msg.cached)
    assert(Dnsruby::PacketSender.recursive_cache_length == 1)
    msg = res.query("example.com")
    assert(msg.cached)
    assert(Dnsruby::PacketSender.recursive_cache_length == 1)
    msg = res.query("google.com")
    assert(!msg.cached)
    assert(Dnsruby::PacketSender.recursive_cache_length == 1)
    msg = res.query("example.com")
    assert(!msg.cached)
    assert(Dnsruby::PacketSender.recursive_cache_length == 1)
    Dnsruby::Cache.max_size=2
    assert(Dnsruby::PacketSender.recursive_cache_length == 1)
    msg = res.query("example.com")
    assert(msg.cached)
    assert(Dnsruby::PacketSender.recursive_cache_length == 1)
    msg = res.query("google.com")
    assert(!msg.cached)
    assert(Dnsruby::PacketSender.recursive_cache_length == 2)
  end

  def test_resolver_do_caching
    #  Get the records back from the test zone
    Dnsruby::PacketSender.clear_caches
    res = Resolver.new()
    res.do_caching = false
    assert(!res.do_caching)
    ret = res.query("example.com")
    assert(!ret.cached)
    assert(ret.rcode == RCode.NoError)
    #  Wait a while
    sleep(1)
    #  Ask for the same records
    ret = res.query("example.com")
    assert(ret.rcode == RCode.NoError)
    assert(!ret.cached)
  end

  def test_online
    #  Get the records back from the test zone
    Dnsruby::PacketSender.clear_caches
    Dnsruby::Recursor.clear_caches
    res = SingleResolver.new("ns.nlnetlabs.nl.")
    # res = SingleResolver.new("ns0.validation-test-servers.nominet.org.uk.")
    res.udp_size = 4096
    query = Message.new("net-dns.org", Types.TXT)
    # query = Message.new("overflow.dnsruby.validation-test-servers.nominet.org.uk", Types.TXT)
    ret = res.send_message(query)
#    print "#{ret}\n"
    assert(!ret.cached)
    assert(ret.rcode == RCode.NoError)
    assert(ret.header.aa)
    #  Store the ttls
    first_ttls = ret.answer.rrset(
      "net-dns.org", Types.TXT).ttl
      # "overflow.dnsruby.validation-test-servers.nominet.org.uk", Types.TXT).ttl
    #  Wait a while
    sleep(1)
    #  Ask for the same records
    query = Message.new("net-dns.org", Types.TXT)
    # query = Message.new("overflow.dnsruby.validation-test-servers.nominet.org.uk", Types.TXT)
    ret = res.send_message(query)
#    print "#{ret}\n"
    assert(ret.rcode == RCode.NoError)
    assert(ret.cached)
    second_ttls = ret.answer.rrset(
      "net-dns.org", Types.TXT).ttl
      # "overflow.dnsruby.validation-test-servers.nominet.org.uk", Types.TXT).ttl
    #  make sure the ttl is less the time we waited
    assert((second_ttls == first_ttls - 1) || (second_ttls == first_ttls - 2),
            "First ttl = #{first_ttls}, second = #{second_ttls}\n")
    #  make sure the header flags (and ID) are right
    assert(ret.header.id == query.header.id, "First id = #{query.header.id}, cached response was #{ret.header.id}\n")
    assert(!ret.header.aa)
  end

  def test_online_uncached
    #  @TODO@ Check that wildcard queries are not cached
  end

end
