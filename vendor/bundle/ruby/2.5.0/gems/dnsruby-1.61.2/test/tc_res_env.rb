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

class TestResolverEnv < Minitest::Test

  include Dnsruby

# @todo@ Dnsruby does not provide this functionality
  def test_res_env
    ENV['RES_NAMESERVERS'] = '10.0.1.128 10.0.2.128';
    ENV['RES_SEARCHLIST']  = 'dnsruby.validation-test-servers.nominet.org.uk lib.dnsruby.validation-test-servers.nominet.org.uk';
    ENV['LOCALDOMAIN']     = 't.dnsruby.validation-test-servers.nominet.org.uk';
    ENV['RES_OPTIONS']     = 'retrans:3 retry:2 debug';


    res = DNS.new;

    assert(res,                       "new() returned something");
    assert(res.config.nameserver,   "nameservers() works");

    servers = res.config.nameserver;

    assert_equal(servers[0], '10.0.1.128',  'Nameserver set correctly');
    assert_equal(servers[1], '10.0.2.128',  'Nameserver set correctly');


    search = res.searchlist;
    assert_equal(search[0], 'dnsruby.validation-test-servers.nominet.org.uk',     'Search set correctly' );
    assert_equal(search[1], 'lib.dnsruby.validation-test-servers.nominet.org.uk', 'Search set correctly' );

    assert_equal(res.domain,  't.dnsruby.validation-test-servers.nominet.org.uk', 'Local domain works'  );
    assert_equal(3, res.retrans,               'Retransmit works'    );
    assert_equal(2, res.retry,                 'Retry works'         );
    assert(res.debug,                    'Debug works'         );


  end
end
