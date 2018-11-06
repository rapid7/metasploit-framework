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

class TestResolverConfig < Minitest::Test

  GoodInput = {
    "port"		  => 54,
    "src_address"        => '10.1.0.1',
    "src_address6"        => 'fc00::1:2:3',
    "src_port"        => 56453,
    "use_tcp"		   => true,
    # 	"stayopen"       => 1,
    "ignore_truncation"          => true,
    "recurse"        => false,
    "packet_timeout"    => 5,
    # 	"dnssec"         => 1,
    # 	"force_v4"       => 1,
  };

  ExtendedInput={
    "query_timeout"        => 30,
    "retry_delay"	       => 6,
    "retry_times"		   => 5,
  }

  LookupInput={
    "domain"	       => 'dnsruby.rubyforge.org',
    "apply_search_list"         => false,
    "ndots"       => 4	,
    "apply_domain" => false
  }

  def setup
    Dnsruby::Config.reset
  end

  def test_multiple_resolver
    res = Dnsruby::Resolver.new({:nameserver => ["127.0.0.1", "::1"]});
    assert(res, "new returned something");
    assert_instance_of(Dnsruby::Resolver, res, "new() returns an object of the correct class.");

    #     assert(res.config.nameserver,       'nameserver() works');

    searchlist = ["t.dnsruby.validation-test-servers.nominet.org.uk", "t2.dnsruby.validation-test-servers.nominet.org.uk"];
    assert_equal(res.config.search=searchlist, searchlist, 'setting searchlist returns correctly.');
    assert_equal(res.config.search,               searchlist, 'setting searchlist stickts.');


    # ~ #diag "\n\nIf you do not have Net::DNS::SEC installed you will see a warning.\n";
    # ~ #diag "It is safe to ignore this\n";

    (GoodInput.merge(ExtendedInput)).each do | param, value |
      #       puts("Setting " + param);
      res.send(param+"=", value)
      assert_equal(res.send(param), value,       "setting #param sticks");
    end;

  end

  def test_single_resolver
    [Dnsruby::SingleResolver.new()].each {|res|
    # [Dnsruby::SingleResolver.new({:nameserver => ["127.0.0.1"]}),
    #   Dnsruby::SingleResolver.new({:nameserver => ["::1"]})].each {|res|
      GoodInput.each do | param, value |
        #       puts("Setting " + param);
        res.send(param+"=", value)
        assert_equal(res.send(param), value,       "setting #param sticks");
      end;
    }
  end

  def test_dns
    res = Dnsruby::DNS.new
    LookupInput.each do | param, value |
      res.config.send(param+"=", value)
      assert_equal(res.config.send(param), value,       "setting #param sticks");
    end;
  end

end
