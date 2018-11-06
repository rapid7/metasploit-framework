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

class TestDNS < Minitest::Test

  include Dnsruby

  def setup
    Dnsruby::Config.reset
  end

  def test_ipv4_address
    Dnsruby::DNS.open { |dns| dns.getnames(Dnsruby::IPv4.create("221.186.184.68")) }
  end

  # def test_resolv_rb_api
  #   DNS.open {|dns|
  #     # dns.getresources("www.ruby-lang.org", Types.A).each  {|r| assert_equal(r.address.to_s, "221.186.184.68")}
  #     dns.getresources("www.ruby-lang.org", Types.A).each  {|r| assert_equal(r.address.to_s, "54.163.249.195")}
  #     r= dns.getresources("ruby-lang.org", Types.MX, Classes.IN).collect {|r| [r.exchange.to_s, r.preference]}
  #     assert_equal(r, [["carbon.ruby-lang.org", 10]])
  #   }
  #   d = DNS.open
  #   # d.getresources("www.ruby-lang.org", Types.A, Classes.IN).each {|r| assert_equal(r.address.to_s, "221.186.184.68")}
  #   d.getresources("www.ruby-lang.org", Types.A, Classes.IN).each {|r| assert_equal(r.address.to_s, "54.163.249.195")}
  #   assert_equal(d.getaddress("www.ruby-lang.org").to_s, "54.163.249.195")
  #   # assert_equal(d.getaddress("www.ruby-lang.org").to_s, "221.186.184.68")
  #   r = d.getaddresses("www.ruby-lang.org")
  #   assert_equal(r.length, 1)
  #   assert_equal(r[0].to_s, "221.186.184.68")
  #   d.each_address("www.ruby-lang.org") {|address| assert_equal(address.to_s, "54.163.249.195")}
  #   # d.each_address("www.ruby-lang.org") {|address| assert_equal(address.to_s, "221.186.184.68")}
  #   assert_equal(d.getname("210.251.121.214").to_s, "ci.ruby-lang.org")
  #   r = d.getnames("210.251.121.214")
  #   assert_equal(r.length, 1)
  #   assert_equal(r[0].to_s, "ci.ruby-lang.org")
  #   d.each_name("210.251.121.214") {|name| assert_equal(name.to_s, "ci.ruby-lang.org")}
  #   r = d.getresource("www.ruby-lang.org", Types.A)
  #   assert_equal(r.name.to_s, "carbon.ruby-lang.org")
  #   assert_equal(r.address.to_s, "221.186.184.68")
  #   assert_equal(r.klass, Classes.IN)
  #   assert_equal(r.type, Types.A)
  #   r = d.getresources("www.ruby-lang.org", Types.MX)
  #   assert(r.length==1)
  #   assert_equal(r[0].name.to_s, "carbon.ruby-lang.org")
  #   assert_equal(r[0].preference, 10)
  #   assert_equal(r[0].exchange.to_s, "carbon.ruby-lang.org")
  #   assert_equal(r[0].klass, Classes.IN)
  #   assert_equal(r[0].type, Types.MX)
  #   r = d.each_resource("www.ruby-lang.org", Types.ANY) {|r|
  #     assert_equal(r.name.to_s, "www.ruby-lang.org")
  #     assert_equal(r.domainname.to_s, "carbon.ruby-lang.org")
  #     assert_equal(r.klass, Classes.IN)
  #     assert_equal(r.type, Types.CNAME)
  #   }
  #   d.close
  # end

  def test_async_api
    # @TODO@ Do we really want an async API for Resolv/DNS?
    # Or would users be better off with Resolver async API?
  end

  def test_concurrent
    # @TODO@ What kind of concurrent testing are we going to do on the top-level API?
  end

  def test_bad_input
    # 
    #  Check that new() is vetting things properly.
    # 
    Dnsruby.log.level=Logger::FATAL
    [:nameserver].each do |test|
#      [{}, 'kjghdfkjhase',1,'\1',nil].each do |input|
# Config now only checks that an IPv4, IPv6 or Name can be made with each input
      [{},1,nil].each do |input|
        res=nil
        begin
          res = Dnsruby::DNS.new({test => input})
          assert(false, "Accepted invalid input")
        rescue
          assert(res==nil, "No resolver should be returned for #{test} = #{input}")
        end
      end
    end
  end

  def test_online
    res = DNS.new
    rrs = [
    {
      :type   		=> Types.A,
      :name   		=> 'a.t.net-dns.org',
      # :name   		=> 'a.t.dnsruby.validation-test-servers.nominet.org.uk',
      :address 	=> '10.0.1.128'
    },
    {
      :type		=> Types::MX,
      :name		=> 'mx.t.net-dns.org',
      :exchange	=> 'a.t.net-dns.org',
      # :name		=> 'mx.t.dnsruby.validation-test-servers.nominet.org.uk',
      # :exchange	=> 'a.t.dnsruby.validation-test-servers.nominet.org.uk',
      :preference 	=> 10
    },
    {
      :type		=> 'CNAME',
      :name		=> 'cname.t.net-dns.org',
      :domainname		=> 'a.t.net-dns.org'
      # :name		=> 'cname.t.dnsruby.validation-test-servers.nominet.org.uk',
      # :domainname		=> 'a.t.dnsruby.validation-test-servers.nominet.org.uk'
    },
    {
      :type		=> Types.TXT,
      :name		=> 'txt.t.net-dns.org',
      # :name		=> 'txt.t.dnsruby.validation-test-servers.nominet.org.uk',
      :strings		=> ['Net-DNS']
    }
    ]

    rrs.each do |data|
      answer = res.getresource(data[:name], data[:type])
      assert(answer)
      assert_equal(answer.klass,    'IN',             'Class correct'           )

      packet, queried_name = res.send_query(data[:name], data[:type])

      assert(packet, "Got an answer for #{data[:name]} IN #{data[:type]}")
      assert_equal(1, packet.header.qdcount, 'Only one question')
      # assert_equal(1, answer.length, 'Got single answer')

      question = (packet.question)[0]
      answer   = (packet.answer)[0]

      assert(question,                           'Got question'            )
      assert_equal(data[:name],  question.qname.to_s,  'Question has right name' )
      assert_equal(data[:name],  queried_name.to_s,  'queried_name has right name' )
      assert_equal(Types.new(data[:type]),  question.qtype,  'Question has right type' )
      assert_equal('IN',             question.qclass.string, 'Question has right class')

      assert(answer)
      assert_equal(answer.klass,    'IN',             'Class correct'           )


      data.keys.each do |meth|
        if (meth == :type)
          assert_equal(Types.new(data[meth]).to_s, answer.send(meth).to_s, "#{meth} correct (#{data[:name]})")
        else
          assert_equal(data[meth].to_s, answer.send(meth).to_s, "#{meth} correct (#{data[:name]})")
        end
      end
    end # do
  end # test_online

  def test_search_query_reverse
    # 
    #  test that getname() DTRT with reverse lookups
    # 
    tests = [
    {
      :ip => '198.41.0.4',
      :host => 'a.root-servers.net',
    },
    {
      :ip => '2001:500:1::803f:235',
      :host => 'h.root-servers.net',
    },
    ]

    res = DNS.new
    tests.each do |test|
      name = res.getname(test[:ip])

      assert_instance_of(Name,name)

      next unless name

      assert_equal(name.to_s, test[:host], "getname(#{test[:ip]}) works")
    end # do
  end # test

  def test_searchlist
    res = DNS.new(
                  :domain     => 't.net-dns.org',
    :search => ["t.net-dns.org", "net-dns.org"]
    #               :domain     => 't.dnsruby.validation-test-servers.nominet.org.uk',
    # :search => ["t.dnsruby.validation-test-servers.nominet.org.uk", "dnsruby.validation-test-servers.nominet.org.uk"]
    )

    # 
    #  test the send_query() appends the default domain and
    #  searchlist correctly.
    # 
    # @TODO@ Should really be done in Config test!

    tests = [
    {
      :method => 'search',
      :name   => 'a'
    },
    {
      :method => 'search',
      :name   => 'a.t'
    },
    {
      :method => 'query',
      :name   => 'a'
    }
    ]

    # res.send_query("a.t.dnsruby.validation-test-servers.nominet.org.uk",  "A")
    res.send_query("a.t.net-dns.org",  "A")
    res.config.ndots=2

    tests.each do |test|
      method = test[:method]

      if (method=="query")
        res.config.apply_search_list=false
      else
        res.config.apply_search_list=true
      end

      ans, query = res.send_query(test[:name])

      assert_instance_of(Message, ans)

      # assert_equal(2, ans.header.ancount, "Correct answer count (with persistent socket and #{method})")

      a = ans.answer

      assert_instance_of(RR::IN::A, a[0])
      assert_equal(a[0].name.to_s, 'a.t.net-dns.org',"Correct name (with persistent socket and #{method})")
      # assert_equal(a[0].name.to_s, 'a.t.dnsruby.validation-test-servers.nominet.org.uk',"Correct name (with persistent socket and #{method})")
    end

    def test_port
      d = DNS.new({:port => 5353})
      assert_true(d.to_s.include?"5353")
    end

  end
end
