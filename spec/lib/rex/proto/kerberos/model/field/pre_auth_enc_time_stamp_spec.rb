# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

describe Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp do

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

=begin
#<OpenSSL::ASN1::Sequence:0x007ff70196b158
  @infinite_length=false,
  @tag=16,
  @tag_class=:UNIVERSAL,
  @tagging=nil,
  @value=
    [
    #<OpenSSL::ASN1::ASN1Data:0x007ff70196b2c0
      @infinite_length=false,
      @tag=0,
      @tag_class=:CONTEXT_SPECIFIC,
      @value=
        [#<OpenSSL::ASN1::Integer:0x007ff70196b2e8
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff70196b338>>
        ]>,
    #<OpenSSL::ASN1::ASN1Data:0x007ff70196b1a8
      @infinite_length=false,
      @tag=2,
      @tag_class=:CONTEXT_SPECIFIC,
      @value=
        [#<OpenSSL::ASN1::OctetString:0x007ff70196b1f8
          @infinite_length=false,
          @tag=4,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
          "`\xAES\xA5\vV.Fa\xD9\xD6\x89\x98\xFCy\x9DEs}\r\x8Ax\x84M\xD7|\xC6P\b\x8D\xAB\"y\xC3\x8D\xD3\xAF\x9F^\xB7\xB8\x9BW\xC5\xC9\xC5\xEA\x90\x89\xC3cX">
        ]>
    ]>
=end
  let(:sample_encrypted_data) do
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

  describe ".decrypt" do
    context "correct key" do
      it "returns the decoded Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp" do
        expect(described_class.decrypt(sample_encrypted_data, 'juan')).to be_a(Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp)
      end
    end

    context "incorrect key" do
      it "raises RuntimeError when decrypting with the incorrect key" do
        expect { described_class.decrypt(sample_encrypted_data, 'error') }.to raise_error(RuntimeError)
      end
    end
  end

  describe "#decrypt" do
    context "correct key" do
      it "returns the decoded Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp" do
        expect(pre_auth_enc_time_stamp.decrypt(sample_encrypted_data, 'juan')).to eq(pre_auth_enc_time_stamp)
      end

      it "decodes pa_time_stamp correctly" do
        pre_auth_enc_time_stamp.decrypt(sample_encrypted_data, 'juan')
        expect(pre_auth_enc_time_stamp.pa_time_stamp.to_s).to eq('2014-12-09 01:09:09 UTC')
      end

      it "decodes pausec correctly" do
        pre_auth_enc_time_stamp.decrypt(sample_encrypted_data, 'juan')
        expect(pre_auth_enc_time_stamp.pausec).to eq(589000)
      end
    end

    context "when incorrect key" do
      it "raises RuntimeError when decrypting with the incorrect key" do
        expect { pre_auth_enc_time_stamp.decrypt(sample_encrypted_data, 'error') }.to raise_error(RuntimeError)
      end
    end
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::Model::Field::PreAuthEncTimeStamp correctly" do
      pre_auth_enc_time_stamp.decode(time_stamp_raw)
      expect(pre_auth_enc_time_stamp.encode).to eq(time_stamp_raw)
    end
  end

end
