
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

class TestSSHFP < Minitest::Test

  include Dnsruby

  def test_sshfp
    txt = "apt-blade6.nominet.org.uk. 85826 IN	SSHFP	1 1 6D4CF7C68E3A959990855099E15D6E0D4DEA4FFF"
    sshfp = RR.create(txt)
    assert(sshfp.type == Types.SSHFP)
    assert(sshfp.alg == RR::SSHFP::Algorithms.RSA)
    assert(sshfp.fptype == RR::SSHFP::FpTypes.SHA1)
    assert(sshfp.fp.unpack("H*")[0].upcase == "6D4CF7C68E3A959990855099E15D6E0D4DEA4FFF")

    m = Dnsruby::Message.new
    m.add_additional(sshfp)
    data = m.encode
    m2 = Dnsruby::Message.decode(data)
    sshfp2 = m2.additional()[0]
    assert(sshfp.fptype == sshfp2.fptype)
    assert(sshfp.alg == sshfp2.alg)
    assert(sshfp.fp == sshfp2.fp)
    assert(sshfp == sshfp2)
  end

end
