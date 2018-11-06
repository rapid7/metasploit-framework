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

class TestAResolverFile < Minitest::Test
  def setup
    Dnsruby::Config.reset
  end

  def test_resFile
    res = Dnsruby::DNS.new("test/resolv.conf")

    assert(res,                "new() returned something")
    assert(res.config.nameserver,   "nameservers() works")

    servers = res.config.nameserver

    assert_equal(servers[0], '10.0.1.128',  'Nameserver set correctly')
    assert_equal(servers[1], '10.0.2.128',  'Nameserver set correctly')


    search = res.config.search
    assert(search.include?('dnsruby.validation-test-servers.nominet.org.uk'),     'Search set correctly' )
    assert(search.include?('lib.dnsruby.validation-test-servers.nominet.org.uk'), 'Search set correctly' )

    assert(res.config.domain=='t.dnsruby.validation-test-servers.nominet.org.uk', 'Local domain works'  )
  end
end
