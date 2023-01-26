# -*- coding:binary -*-
require 'spec_helper'


RSpec.describe Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2 do

  subject(:etype_info2) do
    described_class.new
  end

=begin
[#<OpenSSL::ASN1::Sequence:0x000055eae2f2e478
  @tag=16,
  @value=
    [#<OpenSSL::ASN1::ASN1Data:0x000055eae2f2e540
      @tag=0,
      @value=
        [#<OpenSSL::ASN1::Integer:0x000055eae2f2e568
          @tag=2,
          @value=#<OpenSSL::BN:0x000055eae2f2e590>,
          @tagging=nil,
          @tag_class=:UNIVERSAL,
          @indefinite_length=false>],
      @tag_class=:CONTEXT_SPECIFIC,
      @indefinite_length=false>,
     #<OpenSSL::ASN1::ASN1Data:0x000055eae2f2e4a0 @tag=1,
       @value=
         [#<OpenSSL::ASN1::GeneralString:0x000055eae2f2e4c8 @tag=27,
           @value="POD8.LANw\xC3\xAEth.d\xC3\xAC\xC3\xA1\xC3\xA7ritic\xC5\xA1",
           @tagging=nil,
           @tag_class=:UNIVERSAL,
           @indefinite_length=false>],
       @tag_class=:CONTEXT_SPECIFIC,
       @indefinite_length=false>],
  @tagging=nil,
  @tag_class=:UNIVERSAL,
  @indefinite_length=false>,
#<OpenSSL::ASN1::Sequence:0x000055eae2f2e388
  @tag=16,
  @value=
    [#<OpenSSL::ASN1::ASN1Data:0x000055eae2f2e3b0
      @tag=0,
      @value=
        [#<OpenSSL::ASN1::Integer:0x000055eae2f2e3d8
          @tag=2,
          @value=#<OpenSSL::BN:0x000055eae2f2e400>,
          @tagging=nil,
          @tag_class=:UNIVERSAL,
          @indefinite_length=false>],
      @tag_class=:CONTEXT_SPECIFIC,
      @indefinite_length=false>],
  @tagging=nil,
  @tag_class=:UNIVERSAL,
  @indefinite_length=false>,
#<OpenSSL::ASN1::Sequence:0x000055eae2f2e1f8 
  @tag=16,
  @value=
    [#<OpenSSL::ASN1::ASN1Data:0x000055eae2f2e2c0
      @tag=0,
      @value=
        [#<OpenSSL::ASN1::Integer:0x000055eae2f2e2e8
          @tag=2,
          @value=#<OpenSSL::BN:0x000055eae2f2e310>,
          @tagging=nil,
          @tag_class=:UNIVERSAL,
          @indefinite_length=false>],
      @tag_class=:CONTEXT_SPECIFIC,
      @indefinite_length=false>,
    #<OpenSSL::ASN1::ASN1Data:0x000055eae2f2e220 @tag=1,
      @value=
        [#<OpenSSL::ASN1::GeneralString:0x000055eae2f2e248 @tag=27,
          @value="POD8.LANw\xC3\xAEth.d\xC3\xAC\xC3\xA1\xC3\xA7ritic\xC5\xA1",
          @tagging=nil,
          @tag_class=:UNIVERSAL,
          @indefinite_length=false>],
      @tag_class=:CONTEXT_SPECIFIC,
      @indefinite_length=false>],
  @tagging=nil,
  @tag_class=:UNIVERSAL,
  @indefinite_length=false>]
=end
  let(:etype_info2_encoded) do
    ["30553025a003020112a11e1b1c504f44382e4c414e77c3ae74682e64c3acc3a1c3a77269746963c5a13005a0030201173025a003020103a11e1b1c504f44382e4c414e77c3ae74682e64c3acc3a1c3a77269746963c5a1"].pack('H*')
  end

  describe "#decode" do
    it "returns the correct number of entries" do
      etype_info2.decode(etype_info2_encoded)
      expect(etype_info2.etype_info2_entries.length).to eq(3)
    end

    it "first entry is AES256" do
      etype_info2.decode(etype_info2_encoded)
      expect(etype_info2.etype_info2_entries[0].etype).to eq(18)
    end

    it "first entry salt is decoded" do
      etype_info2.decode(etype_info2_encoded)
      expect(etype_info2.etype_info2_entries[0].salt).to eq("POD8.LANwîth.dìáçriticš")
    end

    it "second entry salt is not present" do
      etype_info2.decode(etype_info2_encoded)
      expect(etype_info2.etype_info2_entries[1].salt).to eq(nil)
    end
  end

  describe "#encode" do
    it "encodes and decodes correctly" do
      entries = []
      one = Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2Entry.new
      one.etype = 1
      one.salt = 'hello'
      one.s2kparams = '0011'
      entries << one

      two = Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2Entry.new
      two.etype = 4
      entries << two

      etype_info2.etype_info2_entries = entries
      encoded = etype_info2.encode
      asn1 = OpenSSL::ASN1.decode(encoded)
      decoded = Rex::Proto::Kerberos::Model::PreAuthEtypeInfo2.decode(encoded)

      expect(decoded.etype_info2_entries.length).to eq(2)
      expect(decoded.etype_info2_entries[0].etype).to eq(1)
      expect(decoded.etype_info2_entries[1].etype).to eq(4)
      
      expect(decoded.etype_info2_entries[0].salt).to eq('hello')
      expect(decoded.etype_info2_entries[1].salt).to eq(nil)

      expect(decoded.etype_info2_entries[0].s2kparams).to eq('0011')
      expect(decoded.etype_info2_entries[1].s2kparams).to eq(nil)
    end
  end
end
