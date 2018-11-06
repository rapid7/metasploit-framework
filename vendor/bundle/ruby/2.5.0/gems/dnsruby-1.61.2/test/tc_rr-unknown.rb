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

class TestRrUnknown < Minitest::Test

  include Dnsruby

  def test_RrUnknown
    assert_equal(10226, Types::typesbyname('TYPE10226'), 'typesbyname(TYPE10226) returns 10226')
    assert_equal('TYPE10226', Types::typesbyval(10226),        'typesbyval(10226) returns TYPE10226')
    assert_equal(Types::typesbyval(1), "A",           '       typesbyval(1) returns A')

    assert_equal(Types::typesbyval(Types.typesbyname('TYPE001')), 'A', 'typesbyval(typebyname(TYPE001)) returns A')


    begin
      Types.typesbyval(0xffff+1)
      flunk("Should fail on large TYPE code")
    rescue Exception
    end

    assert_equal(Classes::classesbyname('CLASS124'), 124,       'classesbyname(CLASS124) returns 124')
    assert_equal(Classes::classesbyval(125),         'CLASS125','classesbyval(125) returns CLASS125')
    assert_equal(Classes::classesbyval(1),           'IN',      'classesbyval(1) returns IN')

    assert_equal('HS', Classes::classesbyval(Classes::classesbyname('CLASS04')), 'classesbyval(typebyname(CLASS04)) returns HS')

    begin
      Classes::classesbyval(0xffff+1)
      flunk("Should fail on large CLASS code")
    rescue Exception
    end
  end

  def test_rr_new
    rr = RR.new_from_string('e.example CLASS01 TYPE01 10.0.0.2')
    assert_equal(RR::IN::A, rr.class,  'TYPE01 parsed OK')
    assert_equal('A', rr.type.string,  'TYPE01 parsed OK')
    assert_equal('IN', rr.klass.string,'CLASS01 parsed OK')
    assert_equal(1, rr.klass.code,'CLASS01 parsed OK')

    rr = RR.new_from_string('e.example IN A \# 4  0A0000 01  ')
    assert_equal('10.0.0.1', rr.address.to_s,'Unknown RR representation for A parsed OK')

    begin
      res=RR.new_from_string('e.example IN A \# 4  0A0000 01 11 ')
      flunk "Should fail on inconsistent length and hex presentation"
    rescue Exception
      # like($@, '/\\\# 4  0A0000 01 11 assert_equal inconsistent\ length does not match content/', 'Fails on inconsassert_equaltent length and hex presentation')
    end


    rr = RR.new_from_string('e.example IN TYPE4555 \# 4  0A0000 01  ')
    assert_equal('e.example	0	IN	TYPE4555	\# 4 0a000001', rr.to_s, 'Fully unknown RR parsed correctly')

    rr4 = RR.new_from_string('e.example. CLASS122 TYPE4555 \# 4  0A0000 01  ')
    assert_equal('e.example.	0	CLASS122	TYPE4555	\# 4 0a000001', rr4.to_s, 'Fully unknown RR in unknown CLASS parsed correctly')
  end

  def test_real_data
    uuencodedPacket=%w{
02 79 85 00 00 01
00 01 00 01 00 01 04 54  45 53 54 07 65 78 61 6d
70 6c 65 03 63 6f 6d 00  00 ff 00 01 c0 0c 30 39
00 01 00 00 00 7b 00 0a  11 22 33 44 55 aa bb cc
dd ee c0 11 00 02 00 01  00 00 03 84 00 05 02 6e
73 c0 11 c0 44 00 01 00  01 00 00 03 84 00 04 7f
00 00 01}

    #     packetdata = uuencodedPacket.pack('H*')
    #     packetdata = packetdata.gsub("\s*", "")

    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')
#    packet     = Net::Packet.new_from_binary(packetdata)
    packet = Message.decode(packetdata)

    string_representation = (packet.answer)[0].to_s
    # string_representation =~ s/\s+/ /g,
    string_representation = string_representation.gsub(/\s+/, " ")
    assert_equal(
	'TEST.example.com. 123 IN TYPE12345 \# 10 1122334455aabbccddee',
    string_representation,
	'Packet read from a packet dumped by bind...'
    )
  end
end
