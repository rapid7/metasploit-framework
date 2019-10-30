# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::PreAuthData do

  subject(:pre_auth_data) do
    described_class.new
  end

=begin
#<OpenSSL::ASN1::Sequence:0x007ff9c500d5e0
 @infinite_length=false,
 @tag=16,
 @tag_class=:UNIVERSAL,
 @tagging=nil,
 @value=
  [#<OpenSSL::ASN1::ASN1Data:0x007ff9c500d6a8
    @infinite_length=false,
    @tag=1,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Integer:0x007ff9c500d6d0
       @infinite_length=false,
       @tag=2,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=#<OpenSSL::BN:0x007ff9c500d6f8>>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c500d608
    @infinite_length=false,
    @tag=2,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::OctetString:0x007ff9c500d630
       @infinite_length=false,
       @tag=4,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=
        "0=\xA0\x03\x02\x01\x17\xA26\x044`\xAES\xA5\vV.Fa\xD9\xD6\x89\x98\xFCy\x9DEs}\r\x8Ax\x84M\xD7|\xC6P\b\x8D\xAB\"y\xC3\x8D\xD3\xAF\x9F^\xB7\xB8\x9BW\xC5\xC9\xC5\xEA\x90\x89\xC3cX">]>]>
=end
  let(:timestamp_sample) do
    "\x30\x48\xa1\x03\x02\x01\x02\xa2\x41\x04\x3f\x30\x3d\xa0\x03\x02" +
    "\x01\x17\xa2\x36\x04\x34\x60\xae\x53\xa5\x0b\x56\x2e\x46\x61\xd9" +
    "\xd6\x89\x98\xfc\x79\x9d\x45\x73\x7d\x0d\x8a\x78\x84\x4d\xd7\x7c" +
    "\xc6\x50\x08\x8d\xab\x22\x79\xc3\x8d\xd3\xaf\x9f\x5e\xb7\xb8\x9b" +
    "\x57\xc5\xc9\xc5\xea\x90\x89\xc3\x63\x58"
  end

=begin
#<OpenSSL::ASN1::Sequence:0x007ff9c30b4888
 @infinite_length=false,
 @tag=16,
 @tag_class=:UNIVERSAL,
 @tagging=nil,
 @value=
  [#<OpenSSL::ASN1::ASN1Data:0x007ff9c30b4950
    @infinite_length=false,
    @tag=1,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Integer:0x007ff9c30b4978
       @infinite_length=false,
       @tag=2,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=#<OpenSSL::BN:0x007ff9c30b49a0>>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c30b48b0
    @infinite_length=false,
    @tag=2,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::OctetString:0x007ff9c30b48d8
       @infinite_length=false,
       @tag=4,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value="0\x05\xA0\x03\x01\x01\x00">]>]>
=end
  let(:pac_sample) do
    "\x30\x11\xa1\x04\x02\x02" +
    "\x00\x80\xa2\x09\x04\x07\x30\x05\xa0\x03\x01\x01\x00"
  end

  describe "#decode" do
    context "when PAC-ENC-TIMESTAMP" do
      it "returns the decoded Rex::Proto::Kerberos::Model::PreAuthData" do
        expect(pre_auth_data.decode(timestamp_sample)).to eq(pre_auth_data)
      end

      it "decodes type" do
        pre_auth_data.decode(timestamp_sample)
        expect(pre_auth_data.type).to eq(2)
      end

      it "decodes value" do
        pre_auth_data.decode(timestamp_sample)
        expect(pre_auth_data.value.length).to eq(63)
      end
    end

    context "when PA-PAC-REQUEST" do
      it "returns the decoded Rex::Proto::Kerberos::Model::PreAuthData" do
        expect(pre_auth_data.decode(pac_sample)).to eq(pre_auth_data)
      end

      it "decodes type" do
        pre_auth_data.decode(pac_sample)
        expect(pre_auth_data.type).to eq(128)
      end

      it "decodes value" do
        pre_auth_data.decode(pac_sample)
        expect(pre_auth_data.value.length).to eq(7)
      end
    end
  end

  describe "#encode" do
    context "when PAC-ENC-TIMESTAMP" do
      it "encodes Rex::Proto::Kerberos::Model::PreAuthData correctly" do
        pre_auth_data.decode(timestamp_sample)
        expect(pre_auth_data.encode).to eq(timestamp_sample)
      end

    end

    context "when PA-PAC-REQUEST" do
      it "encodes Rex::Proto::Kerberos::Model::PreAuthData correctly" do
        pre_auth_data.decode(pac_sample)
        expect(pre_auth_data.encode).to eq(pac_sample)
      end

    end
  end

end
