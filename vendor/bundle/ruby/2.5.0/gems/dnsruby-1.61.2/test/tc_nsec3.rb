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

class Nsec3Test < Minitest::Test

  include Dnsruby

  INPUT = "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 3600 IN NSEC3 1 1 12 aabbccdd ( " +
    "2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG )"
  INPUT2 = "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example. 3600 IN NSEC3 1 1 12 aabbccdd " +
    "2vptu5timamqttgl4luu9kg21e0aor3s"
  def test_nsec_from_string
    nsec = Dnsruby::RR.create(INPUT)
#    assert_equal(H("x.y.w.example"), nsec.next_hashed.to_s)
    assert_equal([Types.A, Types.RRSIG], nsec.types)
    assert(nsec.opt_out?)
    assert_equal(12, nsec.iterations)
    assert_equal("aabbccdd", nsec.salt)
    assert_equal(Dnsruby::Nsec3HashAlgorithms.SHA_1, nsec.hash_alg)

    nsec2 = Dnsruby::RR.create(nsec.to_s)
    assert(nsec2.to_s == nsec.to_s)

    nsec = Dnsruby::RR.create(INPUT2)
    assert_equal([], nsec.types)
    assert(nsec.opt_out?)
    assert_equal(12, nsec.iterations)
    assert_equal("aabbccdd", nsec.salt)
    assert_equal(Dnsruby::Nsec3HashAlgorithms.SHA_1, nsec.hash_alg)

    nsec2 = Dnsruby::RR.create(nsec.to_s)
    assert(nsec2.to_s == nsec.to_s)
  end

  def test_base32
   inputs = [["",""], ["f","CO======"],
     ["fo","CPNG===="], ["foo", "CPNMU==="],
     ["foob", "CPNMUOG="], ["fooba", "CPNMUOJ1"],
     ["foobar", "CPNMUOJ1E8======"]]

    inputs.each {|dec, enc|
      assert(Base32.encode32hex(dec) == enc, "Failed encoding #{dec}")
      assert(Base32.decode32hex(enc) == dec, "Failed decoding #{enc}")
    }
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

  def test_calculate_hash
    input = [
[   "example"       , "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"],
[   "a.example"     , "35mthgpgcu1qg68fab165klnsnk3dpvl"],
[   "ai.example"    , "gjeqe526plbf1g8mklp59enfd789njgi"],
[   "ns1.example"   , "2t7b4g4vsa5smi47k61mv5bv1a22bojr"],
[   "ns2.example"   , "q04jkcevqvmu85r014c7dkba38o0ji5r"],
[   "w.example"     , "k8udemvp1j2f7eg6jebps17vp3n8i58h"],
[   "*.w.example"   , "r53bq7cc2uvmubfu5ocmm6pers9tk9en"],
[   "x.w.example"   , "b4um86eghhds6nea196smvmlo4ors995"],
[   "y.w.example"   , "ji6neoaepv8b5o6k4ev33abha8ht9fgc"],
[   "x.y.w.example" , "2vptu5timamqttgl4luu9kg21e0aor3s"],
[   "xx.example"    , "t644ebqk9bibcna874givr6joj62mlhv"],
[   "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example" , "kohar7mbb8dc2ce8a9qvl8hon4k53uhi"]
    ]
    input.each {|name, hash|
      nsec3 = Dnsruby::RR.create({:type => Dnsruby::Types.NSEC3, :name => name, :salt => "aabbccdd", :iterations => 12, :hash_alg  => 1})
      n = nsec3.calculate_hash
      assert_equal(n, hash, "Expected #{hash} but got #{n} for #{name}")
      c = Dnsruby::RR::NSEC3.calculate_hash(name, 12, Dnsruby::RR::NSEC3.decode_salt("aabbccdd"), 1)
      assert_equal(c, hash, "Expected #{hash} but got #{c} for #{name}")
    }
    # 
  end

  def test_nsec_other_stuff
    nsec = Dnsruby::RR.create(INPUT)
#    begin
#      nsec.salt_length=256
#      fail
#    rescue DecodeError
#    end
#    begin
#      nsec.hash_length=256
#      fail
#    rescue DecodeError
#    end
    #  Be liberal in what you accept...
#    begin
#      nsec.hash_alg = 8
#      fail
#    rescue DecodeError
#    end
    begin
      nsec.flags = 2
      fail
    rescue DecodeError
    end
  end

  def test_nsec_types
    #  Test types in last section to 65536.
    # Test no zeros
    nsec = Dnsruby::RR.create(INPUT)
    nsec.add_type(Types.TYPE65534)
    assert(nsec.types.include?(Types.TYPE65534))
    assert(nsec.to_s.include?(Types.TYPE65534.string))
  end

  def test_types
     rr = RR.create("tfkha3ph6qs16qu3oqtmnfc5tbckpjl7.archi.amt. 1209600 IN NSEC3 1 1 5 -  1tmmto81uc71moj44cli3m6avs5l44l3 NSEC3 CNAME RRSIG    ; flags: optout")
     assert(rr.types.include?(Types::NSEC3))
     assert(rr.types.include?(Types::CNAME))
     assert(rr.types.include?(Types::RRSIG))
     rr = RR.create("929p027vb26s89h6fv5j7hmsis4tcr1p.tjeb.nl.		 3600		 IN		 NSEC3		 1 0 5 beef  9rs4nbe7128ap5i6v196ge2iag5b7rcq A AAAA RRSIG
       ")
  end
end