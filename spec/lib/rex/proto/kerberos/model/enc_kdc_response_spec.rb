# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::EncKdcResponse do

  subject(:enc_kdc_response) do
    described_class.new
  end

=begin
#<OpenSSL::ASN1::ASN1Data:0x007fb7f059e020
 @infinite_length=false,
 @tag=25,
 @tag_class=:APPLICATION,
 @value=
  [#<OpenSSL::ASN1::Sequence:0x007fb7f059e048
    @infinite_length=false,
    @tag=16,
    @tag_class=:UNIVERSAL,
    @tagging=nil,
    @value=
     [#<OpenSSL::ASN1::ASN1Data:0x007fb7f059f308
       @infinite_length=false,
       @tag=0,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007fb7f059f330
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007fb7f059f420
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007fb7f059f448
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007fb7f059f4c0>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007fb7f059f358
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::OctetString:0x007fb7f059f380
                @infinite_length=false,
                @tag=4,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value="\xCAZJb\x9F\xE5r\xC3\xDB\xD3\xBE\xAC^\xC6j\xC7">]>]>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059efe8
       @infinite_length=false,
       @tag=1,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007fb7f059f010
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::Sequence:0x007fb7f059f038
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::ASN1Data:0x007fb7f059f1c8
                @infinite_length=false,
                @tag=0,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Integer:0x007fb7f059f1f0
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=#<OpenSSL::BN:0x007fb7f059f218>>]>,
               #<OpenSSL::ASN1::ASN1Data:0x007fb7f059f060
                @infinite_length=false,
                @tag=1,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::GeneralizedTime:0x007fb7f059f088
                   @infinite_length=false,
                   @tag=24,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=2014-12-09 01:09:09 UTC>]>]>]>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059ef20
       @infinite_length=false,
       @tag=2,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007fb7f059ef48
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007fb7f059ef70>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059ede0
       @infinite_length=false,
       @tag=3,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralizedTime:0x007fb7f059ee08
          @infinite_length=false,
          @tag=24,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=2015-01-05 16:08:29 UTC>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059ed40
       @infinite_length=false,
       @tag=4,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::BitString:0x007fb7f059ed68
          @infinite_length=false,
          @tag=3,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @unused_bits=0,
          @value="P\xE0\x00\x00">]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059ec00
       @infinite_length=false,
       @tag=5,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralizedTime:0x007fb7f059ec28
          @infinite_length=false,
          @tag=24,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=2014-12-09 01:09:09 UTC>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059eac0
       @infinite_length=false,
       @tag=6,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralizedTime:0x007fb7f059eae8
          @infinite_length=false,
          @tag=24,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=2014-12-09 01:09:09 UTC>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059e8e0
       @infinite_length=false,
       @tag=7,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralizedTime:0x007fb7f059e908
          @infinite_length=false,
          @tag=24,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=2014-12-09 11:09:09 UTC>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059e728
       @infinite_length=false,
       @tag=8,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralizedTime:0x007fb7f059e778
          @infinite_length=false,
          @tag=24,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=2014-12-16 01:09:09 UTC>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059e638
       @infinite_length=false,
       @tag=9,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralString:0x007fb7f059e660
          @infinite_length=false,
          @tag=27,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value="DEMO.LOCAL">]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb7f059e070
       @infinite_length=false,
       @tag=10,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007fb7f059e250
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007fb7f059e480
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007fb7f059e4a8
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007fb7f059e4d0>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007fb7f059e2c8
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007fb7f059e2f0
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::GeneralString:0x007fb7f059e390
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="krbtgt">,
                  #<OpenSSL::ASN1::GeneralString:0x007fb7f059e340
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="DEMO.LOCAL">]>]>]>]>]>]>
=end
  let(:enc_as_resp) do
    "\x79\x81\xdd\x30\x81\xda\xa0\x1b\x30\x19\xa0\x03\x02\x01\x17\xa1" +
    "\x12\x04\x10\xca\x5a\x4a\x62\x9f\xe5\x72\xc3\xdb\xd3\xbe\xac\x5e" +
    "\xc6\x6a\xc7\xa1\x1c\x30\x1a\x30\x18\xa0\x03\x02\x01\x00\xa1\x11" +
    "\x18\x0f\x32\x30\x31\x34\x31\x32\x30\x39\x30\x31\x30\x39\x30\x39" +
    "\x5a\xa2\x06\x02\x04\x18\xf4\x10\x2c\xa3\x11\x18\x0f\x32\x30\x31" +
    "\x35\x30\x31\x30\x35\x31\x36\x30\x38\x32\x39\x5a\xa4\x07\x03\x05" +
    "\x00\x50\xe0\x00\x00\xa5\x11\x18\x0f\x32\x30\x31\x34\x31\x32\x30" +
    "\x39\x30\x31\x30\x39\x30\x39\x5a\xa6\x11\x18\x0f\x32\x30\x31\x34" +
    "\x31\x32\x30\x39\x30\x31\x30\x39\x30\x39\x5a\xa7\x11\x18\x0f\x32" +
    "\x30\x31\x34\x31\x32\x30\x39\x31\x31\x30\x39\x30\x39\x5a\xa8\x11" +
    "\x18\x0f\x32\x30\x31\x34\x31\x32\x31\x36\x30\x31\x30\x39\x30\x39" +
    "\x5a\xa9\x0c\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xaa" +
    "\x1f\x30\x1d\xa0\x03\x02\x01\x01\xa1\x16\x30\x14\x1b\x06\x6b\x72" +
    "\x62\x74\x67\x74\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c"
  end

  describe "#decode" do
    context "when AS Response Encrypted Part" do
      it "returns the Rex::Proto::Kerberos::Model::EncKdcResponse decoded" do
        expect(enc_kdc_response.decode(enc_as_resp)).to eq(enc_kdc_response)
      end

      it "decodes the key correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.key.type).to eq(Rex::Proto::Kerberos::Crypto::RC4_HMAC)
      end

      it "decodes the last_req correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.last_req[0].value.to_s).to eq('2014-12-09 01:09:09 UTC')
      end

      it "decodes the nonce correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.nonce).to eq(418648108)
      end

      it "decodes the key_expiration correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.key_expiration.to_s).to eq('2015-01-05 16:08:29 UTC')
      end

      it "decodes the flags correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.flags).to eq(0)
      end

      it "decodes the auth_time correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.auth_time.to_s).to eq('2014-12-09 01:09:09 UTC')
      end

      it "decodes the start_time correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.start_time.to_s).to eq('2014-12-09 01:09:09 UTC')
      end

      it "decodes the end_time correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.end_time.to_s).to eq('2014-12-09 11:09:09 UTC')
      end

      it "decodes the renew_till correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.renew_till.to_s).to eq('2014-12-16 01:09:09 UTC')
      end

      it "decodes the srealm correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.srealm).to eq('DEMO.LOCAL')
      end

      it "decodes the sname correctly" do
        enc_kdc_response.decode(enc_as_resp)
        expect(enc_kdc_response.sname.name_string).to eq(['krbtgt', 'DEMO.LOCAL'])
      end
    end
  end
end
