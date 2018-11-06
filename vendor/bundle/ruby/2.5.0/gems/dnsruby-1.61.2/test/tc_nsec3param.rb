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

class Nsec3ParamTest < Minitest::Test

  include Dnsruby

  INPUT = "example. 3600 IN NSEC3PARAM 1 0 12 aabbccdd"

  def test_nsec_from_string
    nsec = Dnsruby::RR.create(INPUT)

    assert_equal(Dnsruby::Nsec3HashAlgorithms.SHA_1, nsec.hash_alg)
    assert_equal(0, nsec.flags)
    assert_equal(12, nsec.iterations)
    assert_equal("aabbccdd", nsec.salt)

    nsec2 = Dnsruby::RR.create(nsec.to_s)
    assert(nsec2.to_s == nsec.to_s)
  end

  def test_nsec_from_data
    nsec = Dnsruby::RR.create(INPUT)
    m = Dnsruby::Message.new
    m.add_additional(nsec)
    data = m.encode
    m2 = Dnsruby::Message.decode(data)
    nsec3 = m2.additional()[0]
    assert_equal(nsec.to_s, nsec3.to_s)

  end

  def test_from_real_string
    r = Dnsruby::RR.create("tjeb.nl.		 3600		 IN		 NSEC3PARAM		 1 0 5 beef")
    assert_equal(Dnsruby::Name.create("tjeb.nl."), r.name)
    assert_equal("beef", r.salt)
    assert_equal(Dnsruby::Nsec3HashAlgorithms.SHA_1, r.hash_alg)
  end

end