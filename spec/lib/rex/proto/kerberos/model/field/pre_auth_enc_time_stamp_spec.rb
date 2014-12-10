# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

describe Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp do

  subject(:pre_auth_enc_time_stamp) do
    described_class.new
  end

=begin
#<OpenSSL::ASN1::Sequence:0x007ff9c1892de0
 @infinite_length=false,
 @tag=16,
 @tag_class=:UNIVERSAL,
 @tagging=nil,
 @value=
  [#<OpenSSL::ASN1::ASN1Data:0x007ff9c1893538
    @infinite_length=false,
    @tag=0,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Integer:0x007ff9c18936a0
       @infinite_length=false,
       @tag=2,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=#<OpenSSL::BN:0x007ff9c1893a10>>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c1892e58
    @infinite_length=false,
    @tag=2,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::OctetString:0x007ff9c1893150
       @infinite_length=false,
       @tag=4,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=
        "`\xAES\xA5\vV.Fa\xD9\xD6\x89\x98\xFCy\x9DEs}\r\x8Ax\x84M\xD7|\xC6P\b\x8D\xAB\"y\xC3\x8D\xD3\xAF\x9F^\xB7\xB8\x9BW\xC5\xC9\xC5\xEA\x90\x89\xC3cX">]>]>
=end
  let(:sample) do
    "\x30\x3d\xa0\x03\x02\x01\x17\xa2\x36\x04\x34\x60\xae\x53\xa5\x0b" +
    "\x56\x2e\x46\x61\xd9\xd6\x89\x98\xfc\x79\x9d\x45\x73\x7d\x0d\x8a" +
    "\x78\x84\x4d\xd7\x7c\xc6\x50\x08\x8d\xab\x22\x79\xc3\x8d\xd3\xaf" +
    "\x9f\x5e\xb7\xb8\x9b\x57\xc5\xc9\xc5\xea\x90\x89\xc3\x63\x58"
  end

  describe ".new" do
    it "returns a Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp" do
      expect(pre_auth_enc_time_stamp).to be_a(Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp)
    end
  end

  describe "#decode" do
    it "returns the decoded Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp" do
      expect(pre_auth_enc_time_stamp.decode(sample)).to eq(pre_auth_enc_time_stamp)
    end

    it "decodes etype" do
      pre_auth_enc_time_stamp.decode(sample)
      expect(pre_auth_enc_time_stamp.etype).to eq(23)
    end
  end

end
