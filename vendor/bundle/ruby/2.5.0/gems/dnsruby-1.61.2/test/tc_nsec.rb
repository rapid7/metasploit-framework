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

class NsecTest < Minitest::Test

  include Dnsruby

  INPUT = "alfa.example.com. 86400 IN NSEC host.example.com. ( " +
    "A MX RRSIG NSEC TYPE1234 )"
  def test_nsec_from_string
    nsec = Dnsruby::RR.create(INPUT)
    assert_equal("host.example.com", nsec.next_domain.to_s)
    assert_equal([Types.A, Types.MX, Types.RRSIG, Types.NSEC, Types.TYPE1234], nsec.types)

    nsec2 = Dnsruby::RR.create(nsec.to_s)
    assert(nsec2.to_s == nsec.to_s)

    s = "tjeb.nl.		3600	IN	NSEC	dragon.tjeb.nl. A NS SOA MX AAAA RRSIG NSEC DNSKEY"
    nsec = Dnsruby::RR.create(s)
    assert(nsec.types.include?(Types.A))
    assert(nsec.types.include?(Types.DNSKEY))
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

  def test_nsec_types
    #  Test types in last section to 65536.
    # Test no zeros
    nsec = Dnsruby::RR.create(INPUT)
    nsec.add_type(Types.TYPE65534)
    assert(nsec.types.include?(Types.TYPE65534))
    assert(nsec.to_s.include?(Types.TYPE65534.string))
  end

  def test_examples_from_rfc_4035_name_error
    #  Grab the example responses from RFC4035 and make sure that they pass.
    #  Then, try changing some of the NSEC values (ignoring the RRSIGs for now)
    #  and make sure that they fail verification for that reason
    m = Message.new
    m.header.rcode = 3
    m.add_question(Question.new("m1.example."))
    m.add_authority(RR.create("example.       3600 IN SOA ns1.example. bugs.x.w.example. (
                              1081539377
                              3600
                              300
                              3600000
                              3600
                              )"))
    m.add_authority(RR.create("m3.example.     3600 NSEC   ns1.example. NS RRSIG NSEC"))
    m.add_authority(RR.create("example.       3600 NSEC   a.example. NS SOA MX RRSIG NSEC DNSKEY"))
    m.add_authority(RR.create("example.       3600 RRSIG  NSEC 5 1 3600 20040509183619 (
                              20040409183619 38519 example.
                              O0k558jHhyrC97ISHnislm4kLMW48C7U7cBm
                              FTfhke5iVqNRVTB1STLMpgpbDIC9hcryoO0V
                              Z9ME5xPzUEhbvGnHd5sfzgFVeGxr5Nyyq4tW
                              SDBgIBiLQUv1ivy29vhXy7WgR62dPrZ0PWvm
                              jfFJ5arXf4nPxp/kEowGgBRzY/U= )"))
    begin
      Dnssec.anchor_verifier.verify_nsecs(m)
      fail("Should have failed with bad NSECs")
    rescue VerifyError
    end
    m.authority.delete(RR.create("m3.example.     3600 NSEC   ns1.example. NS RRSIG NSEC"))
    m.add_authority(RR.create("b.example.     3600 NSEC   ns1.example. NS RRSIG NSEC"))
    Dnssec.anchor_verifier.verify_nsecs(m)
    m.authority.delete(RR.create("example.       3600 NSEC   a.example. NS SOA MX RRSIG NSEC DNSKEY"))
    begin
      Dnssec.anchor_verifier.verify_nsecs(m)
      fail("Should have failed with no wildcard proof")
    rescue VerifyError
    end
  end

  def test_examples_from_rfc_4035_no_data
    #  Grab the example responses from RFC4035 and make sure that they pass.
    #  Then, try changing some of the NSEC values (ignoring the RRSIGs for now)
    #  and make sure that they fail verification for that reason
    m = Message.new
    m.header.rcode = 0
    m.add_question(Question.new("ns1.example.", Types.MX))
    m.add_authority(RR.create("example.       3600 IN SOA ns1.example. bugs.x.w.example. (
                              1081539377
                              3600
                              300
                              3600000
                              3600
                              )"))
    m.add_authority(RR.create("m3.example.     3600 NSEC   n1.example. NS RRSIG NSEC"))
    begin
      Dnssec.anchor_verifier.verify_nsecs(m)
      fail("Should have failed with bad NSECs")
    rescue VerifyError
    end
    m.authority.delete(RR.create("m3.example.     3600 NSEC   n1.example. NS RRSIG NSEC"))
    m.add_authority(RR.create("ns1.example.   3600 NSEC   ns2.example. A RRSIG NSEC"))
    Dnssec.anchor_verifier.verify_nsecs(m)
    m.authority.delete(RR.create("ns1.example.   3600 NSEC   ns2.example. A RRSIG NSEC"))
    m.add_authority(RR.create("ns1.example.   3600 NSEC   ns2.example. A RRSIG MX NSEC"))
    begin
      Dnssec.anchor_verifier.verify_nsecs(m)
      fail("Should have failed on type covered")
    rescue VerifyError
    end
  end

  def test_examples_from_rfc_4035_wildcard_expansion
    #  Grab the example responses from RFC4035 and make sure that they pass.
    #  Then, try changing some of the NSEC values (ignoring the RRSIGs for now)
    #  and make sure that they fail verification for that reason
    m = Message.new
    m.header.rcode =
      m.add_question(Question.new("a.z.w.example.", Types.MX))
    m.add_answer(RR.create("a.z.w.example. 3600 IN MX  1 ai.example."))
    m.add_answer(RR.create("a.z.w.example. 3600 RRSIG  MX 5 4 3600 20040509183619 (
                              20040409183619 38519 example.
                              OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2
                              f9AMN1CytCd10cYISAxfAdvXSZ7xujKAtPbc
                              tvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhqe2X
                              TjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw
                              4kX18MMR34i8lC36SR5xBni8vHI= )"))
    m.add_authority(RR.create("x.y.w.example. 3600 NSEC   xx.example. MX RRSIG NSEC"))
    begin
      Dnssec.anchor_verifier.verify_nsecs(m)
      fail("Should have failed with bad number of labels in RRSIG")
    rescue VerifyError
    end
    m.answer.delete(RR.create("a.z.w.example. 3600 RRSIG  MX 5 4 3600 20040509183619 (
                              20040409183619 38519 example.
                              OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2
                              f9AMN1CytCd10cYISAxfAdvXSZ7xujKAtPbc
                              tvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhqe2X
                              TjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw
                              4kX18MMR34i8lC36SR5xBni8vHI= )"))
    m.add_answer(RR.create("a.z.w.example. 3600 RRSIG  MX 5 2 3600 20040509183619 (
                              20040409183619 38519 example.
                              OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2
                              f9AMN1CytCd10cYISAxfAdvXSZ7xujKAtPbc
                              tvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhqe2X
                              TjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw
                              4kX18MMR34i8lC36SR5xBni8vHI= )"))
    Dnssec.anchor_verifier.verify_nsecs(m)
    m.authority.delete(RR.create("x.y.w.example. 3600 NSEC   xx.example. MX RRSIG NSEC"))
    m.add_authority(RR.create("x.y.w.example. 3600 NSEC   z.w.example. MX RRSIG NSEC"))
    begin
      Dnssec.anchor_verifier.verify_nsecs(m)
      fail("Should have failed with bad NSEC")
    rescue VerifyError
    end
  end

  def test_examples_from_rfc_4035_wildcard_no_data
    #  Grab the example responses from RFC4035 and make sure that they pass.
    #  Then, try changing some of the NSEC values (ignoring the RRSIGs for now)
    #  and make sure that they fail verification for that reason
    m = Message.new
    m.header.rcode = 0
    m.add_question(Question.new("a.z.w.example.", Types.AAAA))
    m.add_authority(RR.create("example.       3600 IN SOA ns1.example. bugs.x.w.example. (
                              1081539377
                              3600
                              300
                              3600000
                              3600
                              )"))
    m.add_authority(RR.create("x.y.w.example. 3600 NSEC   xx.example. MX RRSIG NSEC"))
    m.add_authority(RR.create("*.w.example.   3600 NSEC   x.y.example. MX RRSIG NSEC"))
    begin
      Dnssec.anchor_verifier.verify_nsecs(m)
      fail("Should have failed with bad wildcard expansion")
    rescue VerifyError
    end
    m.authority.delete(RR.create("*.w.example.   3600 NSEC   x.y.example. MX RRSIG NSEC"))
    m.add_authority(RR.create("*.w.example.   3600 NSEC   x.w.example. MX RRSIG NSEC"))
    #   Test bad versions of wildcard no data
    Dnssec.anchor_verifier.verify_nsecs(m)
    m.authority.delete(RR.create("x.y.w.example. 3600 NSEC   xx.example. MX RRSIG NSEC"))
    begin
      Dnssec.anchor_verifier.verify_nsecs(m)
      fail("Should have failed with no nsecs")
    rescue VerifyError
    end
  end

  #  @TODO@ Test referrals
  #   def test_examples_from_rfc_4035_referral_signed
  #     # Grab the example responses from RFC4035 and make sure that they pass.
  #     # Then, try changing some of the NSEC values (ignoring the RRSIGs for now)
  #     # and make sure that they fail verification for that reason
  #     m = Message.new
  #     m.header.rcode = 3
  #     fail
  #   end
  # 
  #   def test_examples_from_rfc_4035_referral_unsigned
  #     # Grab the example responses from RFC4035 and make sure that they pass.
  #     # Then, try changing some of the NSEC values (ignoring the RRSIGs for now)
  #     # and make sure that they fail verification for that reason
  #     m = Message.new
  #     m.header.rcode = 3
  #     fail
  #   end
  # 
end