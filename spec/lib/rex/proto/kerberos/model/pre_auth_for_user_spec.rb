# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Model::PreAuthForUser do

  subject(:pre_auth_for_user) do
    described_class.new
  end

=begin
#<OpenSSL::ASN1::Sequence:0x00007fbb48be6f30
 @indefinite_length=false,
 @tag=16,
 @tag_class=:UNIVERSAL,
 @tagging=nil,
 @value=
  [#<OpenSSL::ASN1::ASN1Data:0x00007fbb2fd24e10
    @indefinite_length=false,
    @tag=0,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=["0\x18\xA0\x03\x02\x01\x01\xA1\x110\x0F\e\rAdministrator"]>,
   #<OpenSSL::ASN1::ASN1Data:0x00007fbb2dc0ab08
    @indefinite_length=false,
    @tag=1,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralString:0x00007fbb7cf94040
       @indefinite_length=false,
       @tag=27,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value="MYLAB.LOCAL">]>,
   #<OpenSSL::ASN1::ASN1Data:0x00007fbb2fee42c8
    @indefinite_length=false,
    @tag=2,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     ["0\x1A\xA0\x04\x02\x02\xFFv\xA1\x12\x04\x10\x04o\f\xFE\x85EJ|\xFB\xDE\xA0k\xD3\xC7_\xDD"]>,
   #<OpenSSL::ASN1::ASN1Data:0x00007fbb39c59cb0
    @indefinite_length=false,
    @tag=3,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralString:0x00007fbb39c5af20
       @indefinite_length=false,
       @tag=27,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value="Kerberos">]>]>
=end
  let(:sample) do
    "\x30\x55\xa0\x1a\x30\x18\xa0\x03\x02\x01\x01\xa1\x11\x30\x0f\x1b" +
    "\x0d\x41\x64\x6d\x69\x6e\x69\x73\x74\x72\x61\x74\x6f\x72\xa1\x0d" +
    "\x1b\x0b\x4d\x59\x4c\x41\x42\x2e\x4c\x4f\x43\x41\x4c\xa2\x1c\x30" +
    "\x1a\xa0\x04\x02\x02\xff\x76\xa1\x12\x04\x10\x04\x6f\x0c\xfe\x85" +
    "\x45\x4a\x7c\xfb\xde\xa0\x6b\xd3\xc7\x5f\xdd\xa3\x0a\x1b\x08\x4b" +
    "\x65\x72\x62\x65\x72\x6f\x73"
  end

  describe "#decode" do
    it "returns the decoded Rex::Proto::Kerberos::Model::PreAuthForUser" do
      expect(pre_auth_for_user.decode(sample)).to eq(pre_auth_for_user)
    end

    it "decodes user_name" do
      pre_auth_for_user.decode(sample)
      expect(pre_auth_for_user.user_name.name_type).to eq(Rex::Proto::Kerberos::Model::NameType::NT_PRINCIPAL)
      expect(pre_auth_for_user.user_name.name_string).to eq(['Administrator'])
    end

    it "decodes user_realm" do
      pre_auth_for_user.decode(sample)
      expect(pre_auth_for_user.user_realm).to eq('MYLAB.LOCAL')
    end

    it "decodes cksum" do
      pre_auth_for_user.decode(sample)
      expect(pre_auth_for_user.cksum.type).to eq(Rex::Proto::Kerberos::Crypto::Checksum::HMAC_MD5)
      expect(pre_auth_for_user.cksum.checksum).to eq("\x04\x6f\x0c\xfe\x85\x45\x4a\x7c\xfb\xde\xa0\x6b\xd3\xc7\x5f\xdd")
    end

    it "decodes auth_package" do
      pre_auth_for_user.decode(sample)
      expect(pre_auth_for_user.auth_package).to eq('Kerberos')
    end
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::Model::PreAuthForUser correctly" do
      pre_auth_for_user.decode(sample)
      expect(pre_auth_for_user.encode).to eq(sample)
    end
  end

end
