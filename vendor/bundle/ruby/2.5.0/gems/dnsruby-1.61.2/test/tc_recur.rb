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

class TestRecur < Minitest::Test
  def test_recur
    Dnsruby::PacketSender.clear_caches
    r = Dnsruby::Recursor.new
#    Dnsruby::TheLog.level = Logger::DEBUG
    ret = r.query("uk", Dnsruby::Types.DNSKEY)
#    print ret
    assert ret, "Query result was nil."
    assert ret.answer.length > 0, "Answer length should > 0, but was #{ret.answer.length}."
#    ret = r.query_dorecursion("aaa.bigzone.uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
#    ret = r.query_dorecursion("uk-dnssec.nic.uk", Dnsruby::Types.DNSKEY)
  end
end
