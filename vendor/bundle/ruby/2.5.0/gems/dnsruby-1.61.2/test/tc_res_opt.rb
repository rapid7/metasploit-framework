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

class TestResOpt < Minitest::Test

  include Dnsruby

  def test_dns_file

    #  .txt because this test will run under windows, unlike the other file
    #  configuration tests.
    res = Dnsruby::DNS.new('test/custom.txt')

    assert(res,                           'new() returned something')
    assert_instance_of(DNS, res, 'new() returns an object of the correct class.')
    assert(res.config.nameserver,       'nameservers() works')

    servers = res.config.nameserver

    assert_equal('10.0.1.42', servers[0],  'Nameserver set correctly')
    assert_equal('10.0.2.42',  servers[1], 'Nameserver set correctly')


    search = res.config.search
    assert(search.include?('alt.dnsruby.validation-test-servers.nominet.org.uk'), 'Search set correctly' )
    assert(search.include?('ext.dnsruby.validation-test-servers.nominet.org.uk'), 'Search set correctly' )

    assert(res.config.domain == 't2.dnsruby.validation-test-servers.nominet.org.uk',  'Local domain works'  )
  end

  def test_resolver_file
    res = Dnsruby::Resolver.new({:config_info => 'test/custom.txt'})
    assert(res.config.nameserver==['10.0.1.42', '10.0.2.42'], res.config.nameserver.to_s)
  end

  def test_no_file
    Dnsruby.log.level=Logger::FATAL
    res=nil
    begin
      res = DNS.new('nosuch.txt')
      assert_equal(["0.0.0.0"], res.nameserver,"No nameservers should be set for #{test} = #{input}")
    rescue Exception
    end
    begin
      res = Resolver.new('nosuch.txt')
      assert_equal(["0.0.0.0"], res.nameserver,"No nameservers should be set for #{test} = #{input}")
    rescue Exception
    end
#    Dnsruby.log.level=Logger::ERROR
  end

  def test_config_hash_singleresolver
    #  Resolver interface gives us : port, TCP, IgnoreTruncation, TSIGkey, timeout
    #  SR : server, local_address, udp_size
    test_config = {
      :server	   => '10.0.0.1',
      :port		   => 54, # SingleResolver and Multi-Resolver
      :src_address        => '10.1.0.1', # SingleResolver and Multi-Resolver
      :src_address6        => 'fc00::1:2:3', # SingleResolver and Multi-Resolver
      :src_port        => 56353, # SingleResolver and Multi-Resolver
      :use_tcp		   => true, # SingleResolver and Multi-Resolver
      :ignore_truncation          => true, # SingleResolver and Multi-Resolver
      :recurse        => false,
      :packet_timeout    => 60, # SingleResolver and Multi-Resolver # Only have one timeout for both UDP and TCP
      :dnssec         => true,
    }

    res = SingleResolver.new(test_config)
    test_config.keys.each do |item|
      assert_equal(test_config[item], res.send(item), "#{item} is correct")
    end
  end

  def test_config_hash_multiresolver
    #  Resolver interface gives us : port, TCP, IgnoreTruncation, TSIGkey, timeout
    #  ER : retries, load_balance. Also loads servers from Config and configures SRs to point to them
    #    Also implements Resolver interface - but iterates this through *all* SRs
    test_config = {
      :nameserver	   => ['10.0.0.1', '10.0.0.2'], # for Multi-Resolver & DNS
      :port		   => 54, # SingleResolver and Multi-Resolver
      :src_address        => '10.1.0.1', # SingleResolver and Multi-Resolver
      :src_address6        => 'fc00::1:2:3', # SingleResolver and Multi-Resolver
      :src_port        => 56753, # SingleResolver and Multi-Resolver
      :retry_delay	       => 6, # DNS and Multi-Resolver
      :retry_times		   => 5, # DNSand Multi-Resolver
      :use_tcp		   => true, # SingleResolver and Multi-Resolver
      :ignore_truncation          => true, # SingleResolver and Multi-Resolver
      :recurse        => false,
      :packet_timeout    => 60, # SingleResolver and Multi-Resolver # Only have one timeout for both UDP and TCP
      :query_timeout    => 60, # Multi-Resolver only
      :dnssec         => true,
    }

    res = Resolver.new(test_config)
    test_config.keys.each do |item|
      if (item==:nameserver)
        assert_equal(res.config.nameserver, test_config[item], "#{item} is correct")
      else
        assert_equal(res.send(item), test_config[item], "#{item} is correct")
      end
    end
  end

  def test_config_hash_lookup
    #  Lookup : can specify resolver, searchpath
    # 
    #  Check that we can set things in new()
    # 
    res=nil

    test_config = {
      :nameserver	   => ['10.0.0.1', '10.0.0.2'], # for Multi-Resolver & DNS
      :domain	       => 'dnsruby.validation-test-servers.nominet.org.uk', # one for DNS only?
      :search	   => ['dnsruby.validation-test-servers.nominet.org.uk', 't.dnsruby.validation-test-servers.nominet.org.uk'], # one for DNS
      :ndots          => 2, # DNS only
      :apply_search_list         => false, # DNS only
      :apply_domain => false, # DNS only
    }

    res = DNS.new(test_config)
    test_config.keys.each do |item|
      assert_equal(res.config.send(item), test_config[item], "#{item} is correct")
    end
  end


  def test_bad_config
    res=nil
    Dnsruby.log.level=Logger::FATAL

    bad_input = {
      :tsig_rr        => 'set',
      :errorstring    => 'set',
      :answerfrom     => 'set',
      :answersize     => 'set',
      :querytime      => 'set',
      :axfr_sel       => 'set',
      :axfr_rr        => 'set',
      :axfr_soa_count => 'set',
      :udppacketsize  => 'set',
      :cdflag         => 'set',
    }
    res=nil
    begin
      res = Resolver.new(bad_input)
    rescue Exception
    end
    if (res)
      bad_input.keys.each do |key|
        begin
          assert_not_equal(res.send(key), 'set', "#{key} is not set")
        rescue Exception
        end
      end
    end

    res=nil
    begin
      res = DNS.new(bad_input)
    rescue Exception
    end
    if (res)
      bad_input.keys.each do |key|
        begin
          assert_not_equal(res.send(key), 'set', "#{key} is not set")
        rescue Exception
        end
      end
#      Dnsruby.log.level=Logger::ERROR
    end
  end
end