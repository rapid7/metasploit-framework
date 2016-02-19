# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::KdcResponse do

  subject(:kdc_response) do
    described_class.new
  end

  let(:msg_type) { 11 }
  let(:as_decrypt_msg_type) { 8 }

=begin
#<OpenSSL::ASN1::ASN1Data:0x007fb67a878ec0
 @infinite_length=false,
 @tag=11,
 @tag_class=:APPLICATION,
 @value=
  [#<OpenSSL::ASN1::Sequence:0x007fb67a878ee8
    @infinite_length=false,
    @tag=16,
    @tag_class=:UNIVERSAL,
    @tagging=nil,
    @value=
     [#<OpenSSL::ASN1::ASN1Data:0x007fb67a879c30
       @infinite_length=false,
       @tag=0,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007fb67a879c58
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007fb67a879c80>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb67a879b90
       @infinite_length=false,
       @tag=1,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007fb67a879bb8
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007fb67a879be0>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb67a879af0
       @infinite_length=false,
       @tag=3,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralString:0x007fb67a879b18
          @infinite_length=false,
          @tag=27,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value="DEMO.LOCAL">]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb67a8798c0
       @infinite_length=false,
       @tag=4,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007fb67a8798e8
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007fb67a879a00
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007fb67a879a28
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007fb67a879a50>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007fb67a879910
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007fb67a879938
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::GeneralString:0x007fb67a879960
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="juan">]>]>]>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb67a879190
       @infinite_length=false,
       @tag=5,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::ASN1Data:0x007fb67a8791b8
          @infinite_length=false,
          @tag=1,
          @tag_class=:APPLICATION,
          @value=
           [#<OpenSSL::ASN1::Sequence:0x007fb67a8791e0
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::ASN1Data:0x007fb67a8797a8
                @infinite_length=false,
                @tag=0,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Integer:0x007fb67a8797d0
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=#<OpenSSL::BN:0x007fb67a8797f8>>]>,
               #<OpenSSL::ASN1::ASN1Data:0x007fb67a879708
                @infinite_length=false,
                @tag=1,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::GeneralString:0x007fb67a879730
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="DEMO.LOCAL">]>,
               #<OpenSSL::ASN1::ASN1Data:0x007fb67a879488
                @infinite_length=false,
                @tag=2,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Sequence:0x007fb67a8794b0
                   @infinite_length=false,
                   @tag=16,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=
                    [#<OpenSSL::ASN1::ASN1Data:0x007fb67a879618
                      @infinite_length=false,
                      @tag=0,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::Integer:0x007fb67a879640
                         @infinite_length=false,
                         @tag=2,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=#<OpenSSL::BN:0x007fb67a879668>>]>,
                     #<OpenSSL::ASN1::ASN1Data:0x007fb67a8794d8
                      @infinite_length=false,
                      @tag=1,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::Sequence:0x007fb67a879500
                         @infinite_length=false,
                         @tag=16,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=
                          [#<OpenSSL::ASN1::GeneralString:0x007fb67a879578
                            @infinite_length=false,
                            @tag=27,
                            @tag_class=:UNIVERSAL,
                            @tagging=nil,
                            @value="krbtgt">,
                           #<OpenSSL::ASN1::GeneralString:0x007fb67a879528
                            @infinite_length=false,
                            @tag=27,
                            @tag_class=:UNIVERSAL,
                            @tagging=nil,
                            @value="DEMO.LOCAL">]>]>]>]>,
               #<OpenSSL::ASN1::ASN1Data:0x007fb67a879208
                @infinite_length=false,
                @tag=3,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Sequence:0x007fb67a879230
                   @infinite_length=false,
                   @tag=16,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=
                    [#<OpenSSL::ASN1::ASN1Data:0x007fb67a879398
                      @infinite_length=false,
                      @tag=0,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::Integer:0x007fb67a8793c0
                         @infinite_length=false,
                         @tag=2,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=#<OpenSSL::BN:0x007fb67a8793e8>>]>,
                     #<OpenSSL::ASN1::ASN1Data:0x007fb67a8792f8
                      @infinite_length=false,
                      @tag=1,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::Integer:0x007fb67a879320
                         @infinite_length=false,
                         @tag=2,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=#<OpenSSL::BN:0x007fb67a879348>>]>,
                     #<OpenSSL::ASN1::ASN1Data:0x007fb67a879258
                      @infinite_length=false,
                      @tag=2,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::OctetString:0x007fb67a879280
                         @infinite_length=false,
                         @tag=4,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=
                          "U\xE7E\xC3o\xA2(G\xAB\x9C\x86\x13\xEB\x1D\xA8\x98\xECg\x1C\x1F\x15Fk\xE0J\xF2M=\xF7\xE41zO\x15/`\xDD\x98\xA8\xE1\x97ko\xC1$Fl\xA9\x1E\xE26'\xE3\xFA\x99\f\x9Bw\f\xE2X\x02h\xC4T*,]lK\xC8\xBC\x04\x8F\nD'x\xDCK>\x01\xBE\xAC\xF7\x8EzP\xC6>w\xD9e$\xD5\x1A\x18\xA1\x84q\x85\x98/T\x8BV\xE3\xFB,\xE20\x84\x06UU\xEA1\x8B\x84\x00\xE3\x1A\xC3\xA8\xC2\xAC\xC0x?Ght\xCCb\xA6\xCF\xF4k\xAE\xAF'\xDE\x1AM\xB7\xA8\x9Fvzy*B\x12{\xD2\xBE\xC9\x98|D8@\xBDI\xCD>\xDCe\xC7\x8BD\xF5\xA5\xD4f\x0E\xFDX\x9D19'\xD7\xFC\x81\a\xA3*\x1C<">]>]>]>]>]>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fb67a878f10
       @infinite_length=false,
       @tag=6,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007fb67a878f38
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007fb67a8790a0
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007fb67a8790c8
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007fb67a8790f0>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007fb67a879000
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007fb67a879028
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007fb67a879050>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007fb67a878f60
             @infinite_length=false,
             @tag=2,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::OctetString:0x007fb67a878f88
                @infinite_length=false,
                @tag=4,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 "\x80\ax6\x16\xC5gc\x83;\xF8Bf\x8A\xEB\xE9\xFE\xBA\x82\x82\x1F=\x15O[p\x19\\\xE2\x02\xD6\xA5\x87S\xBFw#[2)\xDES\xE6\x9D\xE9\xA58qB\xF7\xFE\x93;0O\xBD\x86\xCD+\x88\x84\xB7@v&\xFE\xD69\xA0i\xA3F\x86\xC6\xDF\x1D\xB2\n\x91\xC5lUV\xFE\xFB\xCELWtl*\xFC\xBCnz\x19v \xE8a\xC2\x99\xD0\x85s\x99\xC5\x19X^\xAE\xC4\xBB\x14\xAC7\xC9\x80\xAA\xD4\x9D\x12\xC67R\xB7\xF0l+\xED\xFC\xEB\xF6? \xBDQ\x92M\t\xE5\x877\xA7\xFAZ=\x01v\xF3\a\xB1\x98'\xB5\xAC\xB7\x98\xA4\xA6w\xF1\xA3\xF9\xF1\x9FN\x8E\x9Cm\x1AY\f\x9D\xC6;\xA9rSm\xD5\x1D\x00\\*\xE8\xC8\xC4\xB8\x9C\x1F\x05\x9AF\xE7\xA9\xBAx\xA9\xA5\r\x90\xB9\xA8=\x9D\xC2d\xE7\x8C\xE0\xDA\x82\xE8\xD0<\xD6\xEB\xC4\x06\xF5\x19\x9E4rF\x12\xBA\x06Zu\x95\x01{5@2\xA2\\\a!B'\xE0\xDC\x9B\xFCG">]>]>]>]>]>
=end
  let(:as_response) do
    "\x6b\x82\x02\x53\x30\x82\x02\x4f\xa0\x03\x02\x01" +
    "\x05\xa1\x03\x02\x01\x0b\xa3\x0c\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c" +
    "\x4f\x43\x41\x4c\xa4\x11\x30\x0f\xa0\x03\x02\x01\x01\xa1\x08\x30" +
    "\x06\x1b\x04\x6a\x75\x61\x6e\xa5\x82\x01\x10\x61\x82\x01\x0c\x30" +
    "\x82\x01\x08\xa0\x03\x02\x01\x05\xa1\x0c\x1b\x0a\x44\x45\x4d\x4f" +
    "\x2e\x4c\x4f\x43\x41\x4c\xa2\x1f\x30\x1d\xa0\x03\x02\x01\x01\xa1" +
    "\x16\x30\x14\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\x0a\x44\x45\x4d" +
    "\x4f\x2e\x4c\x4f\x43\x41\x4c\xa3\x81\xd1\x30\x81\xce\xa0\x03\x02" +
    "\x01\x17\xa1\x03\x02\x01\x02\xa2\x81\xc1\x04\x81\xbe\x55\xe7\x45" +
    "\xc3\x6f\xa2\x28\x47\xab\x9c\x86\x13\xeb\x1d\xa8\x98\xec\x67\x1c" +
    "\x1f\x15\x46\x6b\xe0\x4a\xf2\x4d\x3d\xf7\xe4\x31\x7a\x4f\x15\x2f" +
    "\x60\xdd\x98\xa8\xe1\x97\x6b\x6f\xc1\x24\x46\x6c\xa9\x1e\xe2\x36" +
    "\x27\xe3\xfa\x99\x0c\x9b\x77\x0c\xe2\x58\x02\x68\xc4\x54\x2a\x2c" +
    "\x5d\x6c\x4b\xc8\xbc\x04\x8f\x0a\x44\x27\x78\xdc\x4b\x3e\x01\xbe" +
    "\xac\xf7\x8e\x7a\x50\xc6\x3e\x77\xd9\x65\x24\xd5\x1a\x18\xa1\x84" +
    "\x71\x85\x98\x2f\x54\x8b\x56\xe3\xfb\x2c\xe2\x30\x84\x06\x55\x55" +
    "\xea\x31\x8b\x84\x00\xe3\x1a\xc3\xa8\xc2\xac\xc0\x78\x3f\x47\x68" +
    "\x74\xcc\x62\xa6\xcf\xf4\x6b\xae\xaf\x27\xde\x1a\x4d\xb7\xa8\x9f" +
    "\x76\x7a\x79\x2a\x42\x12\x7b\xd2\xbe\xc9\x98\x7c\x44\x38\x40\xbd" +
    "\x49\xcd\x3e\xdc\x65\xc7\x8b\x44\xf5\xa5\xd4\x66\x0e\xfd\x58\x9d" +
    "\x31\x39\x27\xd7\xfc\x81\x07\xa3\x2a\x1c\x3c\xa6\x82\x01\x0c\x30" +
    "\x82\x01\x08\xa0\x03\x02\x01\x17\xa1\x03\x02\x01\x01\xa2\x81\xfb" +
    "\x04\x81\xf8\x80\x07\x78\x36\x16\xc5\x67\x63\x83\x3b\xf8\x42\x66" +
    "\x8a\xeb\xe9\xfe\xba\x82\x82\x1f\x3d\x15\x4f\x5b\x70\x19\x5c\xe2" +
    "\x02\xd6\xa5\x87\x53\xbf\x77\x23\x5b\x32\x29\xde\x53\xe6\x9d\xe9" +
    "\xa5\x38\x71\x42\xf7\xfe\x93\x3b\x30\x4f\xbd\x86\xcd\x2b\x88\x84" +
    "\xb7\x40\x76\x26\xfe\xd6\x39\xa0\x69\xa3\x46\x86\xc6\xdf\x1d\xb2" +
    "\x0a\x91\xc5\x6c\x55\x56\xfe\xfb\xce\x4c\x57\x74\x6c\x2a\xfc\xbc" +
    "\x6e\x7a\x19\x76\x20\xe8\x61\xc2\x99\xd0\x85\x73\x99\xc5\x19\x58" +
    "\x5e\xae\xc4\xbb\x14\xac\x37\xc9\x80\xaa\xd4\x9d\x12\xc6\x37\x52" +
    "\xb7\xf0\x6c\x2b\xed\xfc\xeb\xf6\x3f\x20\xbd\x51\x92\x4d\x09\xe5" +
    "\x87\x37\xa7\xfa\x5a\x3d\x01\x76\xf3\x07\xb1\x98\x27\xb5\xac\xb7" +
    "\x98\xa4\xa6\x77\xf1\xa3\xf9\xf1\x9f\x4e\x8e\x9c\x6d\x1a\x59\x0c" +
    "\x9d\xc6\x3b\xa9\x72\x53\x6d\xd5\x1d\x00\x5c\x2a\xe8\xc8\xc4\xb8" +
    "\x9c\x1f\x05\x9a\x46\xe7\xa9\xba\x78\xa9\xa5\x0d\x90\xb9\xa8\x3d" +
    "\x9d\xc2\x64\xe7\x8c\xe0\xda\x82\xe8\xd0\x3c\xd6\xeb\xc4\x06\xf5" +
    "\x19\x9e\x34\x72\x46\x12\xba\x06\x5a\x75\x95\x01\x7b\x35\x40\x32" +
    "\xa2\x5c\x07\x21\x42\x27\xe0\xdc\x9b\xfc\x47"
  end

  describe "#decode" do
    context "when AS Response" do
      it "returns the Rex::Proto::Kerberos::Model::KdcResponse decoded" do
        expect(kdc_response.decode(as_response)).to eq(kdc_response)
      end

      it "decodes msg_type correctly" do
        kdc_response.decode(as_response)
        expect(kdc_response.msg_type).to eq(msg_type)
      end

      it "decodes crealm correctly" do
        kdc_response.decode(as_response)
        expect(kdc_response.crealm).to eq('DEMO.LOCAL')
      end

      it "decodes crealm correctly" do
        kdc_response.decode(as_response)
        expect(kdc_response.cname.name_string).to eq(['juan'])
      end

      it "retrieves the ticket" do
        kdc_response.decode(as_response)
        expect(kdc_response.ticket.realm).to eq('DEMO.LOCAL')
      end

      it "retrieves the encrypted part" do
        kdc_response.decode(as_response)
        expect(kdc_response.enc_part.cipher.length).to eq(248)
      end
    end
  end
end
