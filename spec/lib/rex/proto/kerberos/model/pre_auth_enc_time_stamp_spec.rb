# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::PreAuthEncTimeStamp do

  subject(:pre_auth_enc_time_stamp) do
    described_class.new
  end

=begin
#<OpenSSL::ASN1::Sequence:0x007ff9c3830210
@infinite_length=false,
@tag=16,
@tag_class=:UNIVERSAL,
@tagging=nil,
@value=
  [#<OpenSSL::ASN1::ASN1Data:0x007ff9c38302d8
    @infinite_length=false,
    @tag=0,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
      [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c3830300
        @infinite_length=false,
        @tag=24,
        @tag_class=:UNIVERSAL,
        @tagging=nil,
        @value=2014-12-09 01:09:09 UTC>]>,
  #<OpenSSL::ASN1::ASN1Data:0x007ff9c3830238
    @infinite_length=false,
    @tag=1,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
      [#<OpenSSL::ASN1::Integer:0x007ff9c3830260
        @infinite_length=false,
        @tag=2,
        @tag_class=:UNIVERSAL,
        @tagging=nil,
        @value=#<OpenSSL::BN:0x007ff9c3830288>>]>]>
=end
  let(:time_stamp_raw) do
    "\x30\x1a\xa0\x11\x18\x0f\x32\x30" +
    "\x31\x34\x31\x32\x30\x39\x30\x31" +
    "\x30\x39\x30\x39\x5a\xa1\x05\x02" +
    "\x03\x08\xfc\xc8"
  end

  let(:msg_type) { 1 }
  let(:password) { 'juan' }
  let(:enc_type) { Rex::Proto::Kerberos::Crypto::RC4_HMAC }

  describe "#decode" do
    it "returns the decoded Rex::Proto::Kerberos::Model::PreAuthEncTimeStamp" do
      expect(pre_auth_enc_time_stamp.decode(time_stamp_raw)).to eq(pre_auth_enc_time_stamp)
    end

    it "decodes pa_time_stamp correctly" do
      pre_auth_enc_time_stamp.decode(time_stamp_raw)
      expect(pre_auth_enc_time_stamp.pa_time_stamp.to_s).to eq('2014-12-09 01:09:09 UTC')
    end

    it "decodes pausec correctly" do
      pre_auth_enc_time_stamp.decode(time_stamp_raw)
      expect(pre_auth_enc_time_stamp.pausec).to eq(589000)
    end
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::Model::PreAuthEncTimeStamp correctly" do
      pre_auth_enc_time_stamp.decode(time_stamp_raw)
      expect(pre_auth_enc_time_stamp.encode).to eq(time_stamp_raw)
    end
  end

  describe "#encrypt" do
    it "returns an String" do
      pre_auth_enc_time_stamp.decode(time_stamp_raw)
      expect(pre_auth_enc_time_stamp.encrypt(enc_type, password)).to be_an(String)
    end

    it "allows decryption" do
      pre_auth_enc_time_stamp.decode(time_stamp_raw)
      cipher = pre_auth_enc_time_stamp.encrypt(enc_type, password)
      ed = Rex::Proto::Kerberos::Model::EncryptedData.new(etype: enc_type, cipher: cipher)
      plain = ed.decrypt(password, msg_type)
      pre_auth_enc_time_stamp.decode(plain)
      expect(pre_auth_enc_time_stamp.pa_time_stamp.to_s).to eq('2014-12-09 01:09:09 UTC')
    end
  end

end
