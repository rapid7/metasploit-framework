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

class RrsetTest < Minitest::Test
  def test_rrset
    rrset = Dnsruby::RRSet.new


    rr=Dnsruby::RR.create({	   :name => "example.com",
        :ttl  => 3600,
        :type         => 'MX',
        :preference   => 10,
        :exchange     => 'mx-exchange.example.com',
      })

    rrset.add(rr)
    rr.preference = 12
    rrset.add(rr)
    rr.preference = 1
    rrset.add(rr)

    canon = rrset.sort_canonical

    assert(1 == canon[0].preference)
    assert(10 == canon[1].preference)
    assert(12 == canon[2].preference)

    assert(rrset.sigs.length == 0)
    assert(rrset.num_sigs == 0)
    assert(rrset.rrs.length == 3)

    #  Check RRSIG records (only of the right type) can be added to the RRSet
    sig = Dnsruby::RR.create({:name=>"example.com",         :ttl  => 3600,
        :type         => 'RRSIG',
        :type_covered  => 'A',
        :original_ttl => 3600,
        :algorithm => Dnsruby::Algorithms::RSASHA1,
        :labels => 3,
        :expiration => Time.mktime(2003,03,22,17,31, 03).to_i,
        :inception => Time.mktime(2003,02,20,17,31,03).to_i,
        :key_tag => 2642
      })
    assert(!rrset.add(sig))
    assert(rrset.sigs.length == 0)
    assert(rrset.num_sigs == 0)
    assert(rrset.rrs.length == 3)
    sig.type_covered = Dnsruby::Types.MX
    assert(rrset.add(sig))
    assert(rrset.sigs.length == 1)
    assert(rrset.num_sigs == 1)
    assert(rrset.rrs.length == 3)
    sig.name="example.co.uk"
    assert(!rrset.add(sig))
    assert(rrset.sigs.length == 1)
    assert(rrset.num_sigs == 1)
    assert(rrset.rrs.length == 3)
  end

  def test_real_rrset
        uuencodedPacket = %w{
7c 7d 81 80 00 01 00 02  00 0b 00 0d 03 6e 73 31
03 6e 69 63 02 75 6b 00  00 ff 00 01 c0 0c 00 01
00 01 00 02 a2 cc 00 04  c3 42 f0 82 c0 0c 00 1c
00 01 00 02 88 93 00 10  2a 01 00 40 10 01 00 35
00 00 00 00 00 00 00 02  c0 10 00 02 00 01 00 02
a2 cc 00 06 03 6e 73 33  c0 10 c0 10 00 02 00 01
00 02 a2 cc 00 06 03 6e  73 35 c0 10 c0 10 00 02
00 01 00 02 a2 cc 00 02  c0 0c c0 10 00 02 00 01
00 02 a2 cc 00 06 03 6e  73 32 c0 10 c0 10 00 02
00 01 00 02 a2 cc 00 06  03 6e 73 62 c0 10 c0 10
00 02 00 01 00 02 a2 cc  00 06 03 6e 73 64 c0 10
c0 10 00 02 00 01 00 02  a2 cc 00 06 03 6e 73 34
c0 10 c0 10 00 02 00 01  00 02 a2 cc 00 06 03 6e
73 36 c0 10 c0 10 00 02  00 01 00 02 a2 cc 00 06
03 6e 73 61 c0 10 c0 10  00 02 00 01 00 02 a2 cc
00 06 03 6e 73 37 c0 10  c0 10 00 02 00 01 00 02
a2 cc 00 06 03 6e 73 63  c0 10 c0 86 00 01 00 01
00 02 96 62 00 04 d9 4f  a4 83 c0 54 00 01 00 01
00 02 96 8e 00 04 d5 db  0d 83 c0 bc 00 01 00 01
00 02 97 08 00 04 c2 53  f4 83 c0 bc 00 1c 00 01
00 02 96 62 00 10 20 01  06 30 01 81 00 35 00 00
00 00 00 00 00 83 c0 66  00 01 00 01 00 02 96 85
00 04 d5 f6 a7 83 c0 ce  00 01 00 01 00 02 96 85
00 04 d5 f8 fe 82 c0 f2  00 01 00 01 00 02 96 85
00 04 d4 79 28 82 c0 e0  00 01 00 01 00 02 97 08
00 04 cc 4a 70 2c c0 e0  00 1c 00 01 00 02 96 62
00 10 20 01 05 02 d3 99  00 00 00 00 00 00 00 00
00 44 c0 98 00 01 00 01  00 02 96 8e 00 04 cc 4a
71 2c c1 04 00 01 00 01  00 02 96 9b 00 04 c7 07
42 2c c0 aa 00 01 00 01  00 02 96 71 00 04 c7 07
43 2c c0 aa 00 1c 00 01  00 02 96 62 00 10 20 01
05 02 10 0e 00 00 00 00  00 00 00 00 00 44
    }
    uuencodedPacket.map!{|e| e.hex}
    packetdata = uuencodedPacket.pack('c*')

    message = Dnsruby::Message.decode(packetdata)
#      message.additional.rrsets.each {|rr| print "RRSet : #{rr}\n"}
        sec_hash = message.section_rrsets(nil, true) # include the OPT record
        sec_hash.each {|section, rrsets|
          rrsets.each {|rrset|
#              print "#{section} rrset : #{rrset}\n"
            rrset.each { |rr|
            }
          }
        }


        sec_hash = message.section_rrsets(nil, true) # include the OPT record
        sec_hash.each {|section, rrsets|
          rrsets.each {|rrset|
#              print "#{section} rrset : #{rrset}\n"
            rrset.each { |rr|
            }
          }
        }
  end
end