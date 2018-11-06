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

class TestNAPTR < Minitest::Test

  include Dnsruby

  def test_naptr
    txt = "example.com. IN NAPTR 100  50  \"s\"  \"z3950+I2L+I2C\"     \"\"  _z3950._tcp.gatech.edu."
    naptr = RR.create(txt)
    assert(naptr.type == Types.NAPTR)
    assert(naptr.order == 100)
    assert(naptr.preference == 50)
    assert(naptr.flags == 's')
    assert(naptr.service == "z3950+I2L+I2C")
    assert(naptr.regexp == "")
    assert(naptr.replacement == Name.create('_z3950._tcp.gatech.edu.'))

    m = Dnsruby::Message.new
    m.add_additional(naptr)
    data = m.encode
    m2 = Dnsruby::Message.decode(data)
    naptr2 = m2.additional()[0]
    assert(naptr2.type == Types.NAPTR)
    assert(naptr2.order == 100)
    assert(naptr2.preference == 50)
    assert(naptr2.flags == "s")
    assert(naptr2.service == "z3950+I2L+I2C")
    assert(naptr2.regexp == "")
    assert(naptr2.replacement == Name.create('_z3950._tcp.gatech.edu.'))

    naptr.flags = "u"
  end

  def test_string
    txt = 'all.rr.org. 7200 IN NAPTR 100 10 "" "" "/urn:cid:.+@([^\\\\.]+\\\\.)(.*)$/\\\\2/i" .'
    rr = RR.create(txt)
    assert(rr.to_s.index('"/urn:cid:.+@([^\\\\.]+\\\\.)(.*)$/\\\\2/i"'), '"/urn:cid:.+@([^\\\\.]+\\\\.)(.*)$/\\\\2/i"' + "\n" + rr.to_s)
  end

  def test_bad_string
    txt = 'all.rr.binary.org.		IN	NAPTR		100   10   ""  ""  "/urn:cid:.+@([^\\.]+\\.)(.*)$/\\\\2/i"    .'
    rr = RR.create(txt)
    assert(rr.to_s.index('"/urn:cid:.+@([^.]+.)(.*)$/\\\\2/i"'), '"/urn:cid:.+@([^.]+.)(.*)$/\\\\2/i"' + "\n" + rr.to_s)
  end

end
