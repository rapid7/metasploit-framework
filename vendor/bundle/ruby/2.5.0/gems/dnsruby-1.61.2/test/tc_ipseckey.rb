
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

class TestIPSECKEY < Minitest::Test

  include Dnsruby

  def test_ipseckey
    [{"38.1.0.192.in-addr.arpa. 7200 IN     IPSECKEY ( 10 3 2
                    mygateway.example.com.
                     AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )" =>
          ["mygateway.example.com", "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
          10, 3, 2]},

      {"38.2.0.192.in-addr.arpa. 7200 IN     IPSECKEY ( 10 1 2
                    192.0.2.38
                    AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )" =>
          ["192.0.2.38", "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==", 10, 1, 2]},
      {"38.2.0.192.in-addr.arpa. 7200 IN     IPSECKEY ( 10 0 2
                    .
                    AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )" =>
          ["", "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==", 10, 0, 2]},
      {"38.2.0.192.in-addr.arpa. 7200 IN     IPSECKEY ( 10 1 2
                    192.0.2.3
                    AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )" =>
          ["192.0.2.3", "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==", 10, 1, 2]},
      {"0.d.4.0.3.0.e.f.f.f.3.f.0.1.2.01.0.0.0.0.0.2.8.B.D.0.1.0.0.2.ip6.arpa. 7200 IN     IPSECKEY ( 10 2 2
                    2001:0DB8:0:8002::2000:1
                    AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ== )" =>
          ["2001:DB8:0:8002::2000:1", "AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
        10, 2, 2]}
    ].each {|hash|
      hash.each {|txt, data|


      ipseckey = RR.create(txt)
      assert(ipseckey.precedence == data[2])
      assert(ipseckey.gateway_type == data[3])
      assert(ipseckey.algorithm == data[4])
      assert(ipseckey.gateway.to_s == data[0])
      assert(ipseckey.public_key_string == data[1])

      m = Dnsruby::Message.new
      m.add_additional(ipseckey)
      data = m.encode
      m2 = Dnsruby::Message.decode(data)
      ipseckey2 = m2.additional()[0]
      assert(ipseckey.gateway_type == ipseckey2.gateway_type)
      assert(ipseckey.algorithm == ipseckey2.algorithm)
      assert(ipseckey.gateway == ipseckey2.gateway)
      assert(ipseckey.klass == ipseckey2.klass)
      assert(ipseckey == ipseckey2)
    }
    }
  end

end
