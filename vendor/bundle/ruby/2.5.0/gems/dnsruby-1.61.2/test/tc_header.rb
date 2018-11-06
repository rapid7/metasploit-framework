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

class TestHeader < Minitest::Test

  include Dnsruby

  def test_header
    header = Header.new();
    assert(header, "new() returned something")

    header.id=41
    assert_equal(header.id, 41, "id() works")

    header.qr=true
    assert_equal(header.qr, true, "qr() works")

    header.opcode="QUERY"
    assert_equal(OpCode.Query, header.opcode,
                      "opcode() works")
    header.opcode=OpCode::Query
    assert_equal(header.opcode.string, "Query",
                      "opcode() works")


    header.aa=true
    assert_equal(header.aa, true, "aa() works")

    header.tc=false
    assert_equal(header.tc, false, "tc() works")

    header.rd=true
    assert_equal(header.rd, true, "rd() works")

    header.ad=true
    assert_equal(header.ad, true, "rd() works")

    header.cd=true
    assert_equal(header.cd, true, "rd() works")

    header.ra=true
    assert_equal(header.ra, true, "ra() works")

    header.qr=true
    assert_equal(header.qr, true, "qr() works")

    header.rcode="NOERROR"
    assert_equal(header.get_header_rcode, RCode::NOERROR, "rcode() works")
    header.rcode=RCode.NOERROR
    assert_equal(header.get_header_rcode.string, "NOERROR", "rcode() works")

    header.qdcount=1
    header.ancount=2
    header.nscount=3
    header.arcount=3


    #  Reenable when support for CD is there
    # header.cd=0
    # assert_equal(header.cd, 0, "cd() works")
    data = header.data

    header2 = Header.new_from_data(data);

    assert(header==(header2), 'Headers are the same');

    header = Header.new;

    # 
    #  Check that the aliases work properly.
    # 
    header.zocount=(0);
    header.prcount=(1);
    header.upcount=(2);
    header.adcount=(3);

    assert_equal(header.zocount, 0, 'zocount works');
    assert_equal(header.prcount, 1, 'prcount works');
    assert_equal(header.upcount, 2, 'upcount works');
    assert_equal(header.adcount, 3, 'adcount works');



  end
end
