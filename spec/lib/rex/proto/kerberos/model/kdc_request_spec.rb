# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::KdcRequest do

  subject(:kdc_request) do
    described_class.new
  end

  let(:as_req) { 10 }
  let(:tgs_req) { 12 }

=begin
#<OpenSSL::ASN1::ASN1Data:0x007ff9c1978200
 @infinite_length=false,
 @tag=10,
 @tag_class=:APPLICATION,
 @value=
  [#<OpenSSL::ASN1::Sequence:0x007ff9c1978250
    @infinite_length=false,
    @tag=16,
    @tag_class=:UNIVERSAL,
    @tagging=nil,
    @value=
     [#<OpenSSL::ASN1::ASN1Data:0x007ff9c1979cb8
       @infinite_length=false,
       @tag=1,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff9c1979d58
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff9c1979d80>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff9c1979bc8
       @infinite_length=false,
       @tag=2,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff9c1979c18
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff9c1979c40>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff9c19793f8
       @infinite_length=false,
       @tag=3,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007ff9c1979448
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::Sequence:0x007ff9c1979740
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::ASN1Data:0x007ff9c1979a10
                @infinite_length=false,
                @tag=1,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Integer:0x007ff9c1979a60
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=#<OpenSSL::BN:0x007ff9c1979a88>>]>,
               #<OpenSSL::ASN1::ASN1Data:0x007ff9c19797b8
                @infinite_length=false,
                @tag=2,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::OctetString:0x007ff9c1979948
                   @infinite_length=false,
                   @tag=4,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=
                    "0=\xA0\x03\x02\x01\x17\xA26\x044`\xAES\xA5\vV.Fa\xD9\xD6\x89\x98\xFCy\x9DEs}\r\x8Ax\x84M\xD7|\xC6P\b\x8D\xAB\"y\xC3\x8D\xD3\xAF\x9F^\xB7\xB8\x9BW\xC5\xC9\xC5\xEA\x90\x89\xC3cX">]>]>,
            #<OpenSSL::ASN1::Sequence:0x007ff9c1979470
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::ASN1Data:0x007ff9c1979678
                @infinite_length=false,
                @tag=1,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Integer:0x007ff9c19796a0
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=#<OpenSSL::BN:0x007ff9c19796c8>>]>,
               #<OpenSSL::ASN1::ASN1Data:0x007ff9c1979510
                @infinite_length=false,
                @tag=2,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::OctetString:0x007ff9c1979538
                   @infinite_length=false,
                   @tag=4,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="0\x05\xA0\x03\x01\x01\x00">]>]>]>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978318
       @infinite_length=false,
       @tag=4,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007ff9c1978368
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007ff9c1979290
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::BitString:0x007ff9c19792b8
                @infinite_length=false,
                @tag=3,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @unused_bits=0,
                @value="P\x80\x00\x00">]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978fe8
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007ff9c1979038
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::ASN1Data:0x007ff9c1979178
                   @infinite_length=false,
                   @tag=0,
                   @tag_class=:CONTEXT_SPECIFIC,
                   @value=
                    [#<OpenSSL::ASN1::Integer:0x007ff9c19791a0
                      @infinite_length=false,
                      @tag=2,
                      @tag_class=:UNIVERSAL,
                      @tagging=nil,
                      @value=#<OpenSSL::BN:0x007ff9c19791c8>>]>,
                  #<OpenSSL::ASN1::ASN1Data:0x007ff9c1979060
                   @infinite_length=false,
                   @tag=1,
                   @tag_class=:CONTEXT_SPECIFIC,
                   @value=
                    [#<OpenSSL::ASN1::Sequence:0x007ff9c1979088
                      @infinite_length=false,
                      @tag=16,
                      @tag_class=:UNIVERSAL,
                      @tagging=nil,
                      @value=
                       [#<OpenSSL::ASN1::GeneralString:0x007ff9c19790b0
                         @infinite_length=false,
                         @tag=27,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value="juan">]>]>]>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978f20
             @infinite_length=false,
             @tag=2,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::GeneralString:0x007ff9c1978f70
                @infinite_length=false,
                @tag=27,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value="DEMO.LOCAL">]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978bb0
             @infinite_length=false,
             @tag=3,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007ff9c1978c00
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::ASN1Data:0x007ff9c1978de0
                   @infinite_length=false,
                   @tag=0,
                   @tag_class=:CONTEXT_SPECIFIC,
                   @value=
                    [#<OpenSSL::ASN1::Integer:0x007ff9c1978e08
                      @infinite_length=false,
                      @tag=2,
                      @tag_class=:UNIVERSAL,
                      @tagging=nil,
                      @value=#<OpenSSL::BN:0x007ff9c1978e58>>]>,
                  #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978ca0
                   @infinite_length=false,
                   @tag=1,
                   @tag_class=:CONTEXT_SPECIFIC,
                   @value=
                    [#<OpenSSL::ASN1::Sequence:0x007ff9c1978cc8
                      @infinite_length=false,
                      @tag=16,
                      @tag_class=:UNIVERSAL,
                      @tagging=nil,
                      @value=
                       [#<OpenSSL::ASN1::GeneralString:0x007ff9c1978d40
                         @infinite_length=false,
                         @tag=27,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value="krbtgt">,
                        #<OpenSSL::ASN1::GeneralString:0x007ff9c1978cf0
                         @infinite_length=false,
                         @tag=27,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value="DEMO.LOCAL">]>]>]>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978a20
             @infinite_length=false,
             @tag=4,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c1978a70
                @infinite_length=false,
                @tag=24,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=1970-01-01 00:00:00 UTC>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978890
             @infinite_length=false,
             @tag=5,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c19788e0
                @infinite_length=false,
                @tag=24,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=1970-01-01 00:00:00 UTC>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978728
             @infinite_length=false,
             @tag=6,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c1978750
                @infinite_length=false,
                @tag=24,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=1970-01-01 00:00:00 UTC>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978610
             @infinite_length=false,
             @tag=7,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007ff9c1978638
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007ff9c19786b0>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c1978390
             @infinite_length=false,
             @tag=8,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007ff9c19783e0
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::Integer:0x007ff9c1978430
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=#<OpenSSL::BN:0x007ff9c19784a8>>]>]>]>]>]>]>
=end
  let(:sample_as_req) do
    "\x6a\x82\x01\x08\x30\x82\x01\x04\xa1\x03\x02\x01" +
    "\x05\xa2\x03\x02\x01\x0a\xa3\x5f\x30\x5d\x30\x48\xa1\x03\x02\x01" +
    "\x02\xa2\x41\x04\x3f\x30\x3d\xa0\x03\x02\x01\x17\xa2\x36\x04\x34" +
    "\x60\xae\x53\xa5\x0b\x56\x2e\x46\x61\xd9\xd6\x89\x98\xfc\x79\x9d" +
    "\x45\x73\x7d\x0d\x8a\x78\x84\x4d\xd7\x7c\xc6\x50\x08\x8d\xab\x22" +
    "\x79\xc3\x8d\xd3\xaf\x9f\x5e\xb7\xb8\x9b\x57\xc5\xc9\xc5\xea\x90" +
    "\x89\xc3\x63\x58\x30\x11\xa1\x04\x02\x02\x00\x80\xa2\x09\x04\x07" +
    "\x30\x05\xa0\x03\x01\x01\x00\xa4\x81\x96\x30\x81\x93\xa0\x07\x03" +
    "\x05\x00\x50\x80\x00\x00\xa1\x11\x30\x0f\xa0\x03\x02\x01\x01\xa1" +
    "\x08\x30\x06\x1b\x04\x6a\x75\x61\x6e\xa2\x0c\x1b\x0a\x44\x45\x4d" +
    "\x4f\x2e\x4c\x4f\x43\x41\x4c\xa3\x1f\x30\x1d\xa0\x03\x02\x01\x01" +
    "\xa1\x16\x30\x14\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\x0a\x44\x45" +
    "\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa4\x11\x18\x0f\x31\x39\x37\x30" +
    "\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a\xa5\x11\x18\x0f\x31" +
    "\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a\xa6\x11" +
    "\x18\x0f\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30" +
    "\x5a\xa7\x06\x02\x04\x18\xf4\x10\x2c\xa8\x05\x30\x03\x02\x01\x17"
  end

=begin
#<OpenSSL::ASN1::ASN1Data:0x007ff9c19bb438
 @infinite_length=false,
 @tag=12,
 @tag_class=:APPLICATION,
 @value=
  [#<OpenSSL::ASN1::Sequence:0x007ff9c19bb460
    @infinite_length=false,
    @tag=16,
    @tag_class=:UNIVERSAL,
    @tagging=nil,
    @value=
     [#<OpenSSL::ASN1::ASN1Data:0x007ff9c3830440
       @infinite_length=false,
       @tag=1,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff9c3830468
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff9c3830490>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff9c38303a0
       @infinite_length=false,
       @tag=2,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff9c38303c8
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff9c38303f0>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bbfa0
       @infinite_length=false,
       @tag=3,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007ff9c3830008
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::Sequence:0x007ff9c38301c0
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::ASN1Data:0x007ff9c3830288
                @infinite_length=false,
                @tag=1,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Integer:0x007ff9c38302b0
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=#<OpenSSL::BN:0x007ff9c38302d8>>]>,
               #<OpenSSL::ASN1::ASN1Data:0x007ff9c38301e8
                @infinite_length=false,
                @tag=2,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::OctetString:0x007ff9c3830210
                   @infinite_length=false,
                   @tag=4,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=
                    "n\x82\x01\xD20\x82\x01\xCE\xA0\x03\x02\x01\x05\xA1\x03\x02\x01\x0E\xA2\a\x03\x05\x00\x00\x00\x00\x00\xA3\x82\x01\x10a\x82\x01\f0\x82\x01\b\xA0\x03\x02\x01\x05\xA1\f\e\nDEMO.LOCAL\xA2\x1F0\x1D\xA0\x03\x02\x01\x01\xA1\x160\x14\e\x06krbtgt\e\nDEMO.LOCAL\xA3\x81\xD10\x81\xCE\xA0\x03\x02\x01\x17\xA1\x03\x02\x01\x02\xA2\x81\xC1\x04\x81\xBEU\xE7E\xC3o\xA2(G\xAB\x9C\x86\x13\xEB\x1D\xA8\x98\xECg\x1C\x1F\x15Fk\xE0J\xF2M=\xF7\xE41zO\x15/`\xDD\x98\xA8\xE1\x97ko\xC1$Fl\xA9\x1E\xE26'\xE3\xFA\x99\f\x9Bw\f\xE2X\x02h\xC4T*,]lK\xC8\xBC\x04\x8F\nD'x\xDCK>\x01\xBE\xAC\xF7\x8EzP\xC6>w\xD9e$\xD5\x1A\x18\xA1\x84q\x85\x98/T\x8BV\xE3\xFB,\xE20\x84\x06UU\xEA1\x8B\x84\x00\xE3\x1A\xC3\xA8\xC2\xAC\xC0x?Ght\xCCb\xA6\xCF\xF4k\xAE\xAF'\xDE\x1AM\xB7\xA8\x9Fvzy*B\x12{\xD2\xBE\xC9\x98|D8@\xBDI\xCD>\xDCe\xC7\x8BD\xF5\xA5\xD4f\x0E\xFDX\x9D19'\xD7\xFC\x81\a\xA3*\x1C<\xA4\x81\xA40\x81\xA1\xA0\x03\x02\x01\x17\xA2\x81\x99\x04\x81\x96m\xB5\xEA5Q&\x94\xF51'\xD1\x00Y\xEDl\xBC ,\x89pz\x14t\xC9\x05\x85\a\xF76S\xCD\x80j\xA1b\xE6s:}q\x83\x1D\x93\xC6t\xC5o{q\x1D\xCE\xD3\vF\x8B\xC1\x13V\xE7\xEE\x8C\xA2\xCC\xA6x\xDE~\x80#9g\xD8,:j\x12> \xC5\xAA\xD0\xAE\xD5^\xB6|\x83f\xFC\xC5e\x1E\xEAb\x97Hh\xDA\x8Eb|\x065}\xC53%\xBC\x93\x8Ad\x16-\xF4\xDE|V\xD0;\x13O/\x86u\x14`\x80Mw\xEB\x04\b\xE6A \xEE\x16\x0F\xE2+v\xD5\x14`-\xF6\xA8\xDE\xF2\xB5">]>]>,
            #<OpenSSL::ASN1::Sequence:0x007ff9c3830030
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::ASN1Data:0x007ff9c38300f8
                @infinite_length=false,
                @tag=1,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Integer:0x007ff9c3830120
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=#<OpenSSL::BN:0x007ff9c3830148>>]>,
               #<OpenSSL::ASN1::ASN1Data:0x007ff9c3830058
                @infinite_length=false,
                @tag=2,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::OctetString:0x007ff9c3830080
                   @infinite_length=false,
                   @tag=4,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="0\x05\xA0\x03\x01\x01\x00">]>]>]>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bb488
       @infinite_length=false,
       @tag=4,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007ff9c19bb4b0
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007ff9c19bbeb0
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::BitString:0x007ff9c19bbed8
                @infinite_length=false,
                @tag=3,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @unused_bits=0,
                @value="P\x80\x00\x00">]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bbe10
             @infinite_length=false,
             @tag=2,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::GeneralString:0x007ff9c19bbe38
                @infinite_length=false,
                @tag=27,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value="DEMO.LOCAL">]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bbb90
             @infinite_length=false,
             @tag=3,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007ff9c19bbbb8
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::ASN1Data:0x007ff9c19bbd20
                   @infinite_length=false,
                   @tag=0,
                   @tag_class=:CONTEXT_SPECIFIC,
                   @value=
                    [#<OpenSSL::ASN1::Integer:0x007ff9c19bbd48
                      @infinite_length=false,
                      @tag=2,
                      @tag_class=:UNIVERSAL,
                      @tagging=nil,
                      @value=#<OpenSSL::BN:0x007ff9c19bbd70>>]>,
                  #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bbbe0
                   @infinite_length=false,
                   @tag=1,
                   @tag_class=:CONTEXT_SPECIFIC,
                   @value=
                    [#<OpenSSL::ASN1::Sequence:0x007ff9c19bbc08
                      @infinite_length=false,
                      @tag=16,
                      @tag_class=:UNIVERSAL,
                      @tagging=nil,
                      @value=
                       [#<OpenSSL::ASN1::GeneralString:0x007ff9c19bbc80
                         @infinite_length=false,
                         @tag=27,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value="krbtgt">,
                        #<OpenSSL::ASN1::GeneralString:0x007ff9c19bbc30
                         @infinite_length=false,
                         @tag=27,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value="DEMO.LOCAL">]>]>]>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bba78
             @infinite_length=false,
             @tag=4,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c19bbaa0
                @infinite_length=false,
                @tag=24,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=1970-01-01 00:00:00 UTC>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bb960
             @infinite_length=false,
             @tag=5,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c19bb988
                @infinite_length=false,
                @tag=24,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=1970-01-01 00:00:00 UTC>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bb848
             @infinite_length=false,
             @tag=6,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c19bb870
                @infinite_length=false,
                @tag=24,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=1970-01-01 00:00:00 UTC>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bb7a8
             @infinite_length=false,
             @tag=7,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007ff9c19bb7d0
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007ff9c19bb7f8>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bb6b8
             @infinite_length=false,
             @tag=8,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007ff9c19bb6e0
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::Integer:0x007ff9c19bb708
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=#<OpenSSL::BN:0x007ff9c19bb730>>]>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bb4d8
             @infinite_length=false,
             @tag=10,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007ff9c19bb500
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::ASN1Data:0x007ff9c19bb5c8
                   @infinite_length=false,
                   @tag=0,
                   @tag_class=:CONTEXT_SPECIFIC,
                   @value=
                    [#<OpenSSL::ASN1::Integer:0x007ff9c19bb5f0
                      @infinite_length=false,
                      @tag=2,
                      @tag_class=:UNIVERSAL,
                      @tagging=nil,
                      @value=#<OpenSSL::BN:0x007ff9c19bb618>>]>,
                  #<OpenSSL::ASN1::ASN1Data:0x007ff9c19bb528
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:CONTEXT_SPECIFIC,
                   @value=
                    [#<OpenSSL::ASN1::OctetString:0x007ff9c19bb550
                      @infinite_length=false,
                      @tag=4,
                      @tag_class=:UNIVERSAL,
                      @tagging=nil,
                      @value=
                       "\x8A0\x9D|\xA7\xE4\"6\rD\xF5\xD1:\x00\x8B7nR \xBC\xEA\x8Bpf\xC0\x90\xC4('1\xCF\x16,| |\xAA<\xE0\xC7j\xFB\xB9A\xB2\xD9\xA2\xD8Y\x92\xB5\x82\x17\x8A\x93VQ\x97\xF9\xAD\x1D\xC6\xC6\xBC\xA0D\x9B\xC5\xC1\xD81\xF1\x94\x887\v\xA5\xAFQ\xB0=\x9Am\xC0\xB2\xF1 3\xB7\x87z\xCF\xF7\xDE\xA0\x8B\x83\xAEvq8}BM\xDE\n\x03\xBE\xB7\x1C\xF4\x8C\x84\x165.`\xC4\x83\x17q\xE7\x00#\xFB\xA1\x01\xD3\xDA\xE0\x7F\xCD\x04=S\x85Nr\tc\xF4\x06\xD8Q\x15\xAB\x15\xECO\x80\xC5\xF3\xE2\x8A\x7F\x97\x0Fq\xED\f\xE9\x9F\x19\x14k=\x94J\xAE>\xB8\x1A3\xC4V\xCF6\xF8V\n\xE9\xAF\\\xB5B@r\xDE\xD5\x957\xA0\xE5\x93\xC32\xEF\x82\n\x0F\x1E\nu \xB6\x8D\xFC\xE2\xCE\xB3\x87\xDF\xA5\x04g\xF40\x1A\n\x198FZXF\xF44\xBA\xDBFN\xC4\xCC\xAA\xBC$\x85\xA5$\x84\x96\xA4uCF\x7F\x11\xCEG\x9F\xFA\x84\xCE\xB65\xCD\x95\x1E\x1D\x03\x88\x1D\xE3:S\x9B\xA5\e\x97\x83\xCF\xB3\x9E\x88\b\x86mH\x98\xEC\x8D\x83B\xAE\xC9\x92V\xD5\xA9\x90\x03G\xB8\xD7\x81\xF4n\x1Ems\x8A:\xC6\x0F\xB18\x99O\x06\x04\x11}\xA394\xA9\x9E\x8EH\xCCd\xF33<\v\x88>B\xF8t>\x92hg&\xEBF\xAA\xC81wK\xB1W\xEFI\xD3\x98\xF5S\xC0X\x19&\xB7\e\x8C\x17w\xBC\xE0 \xE9\x80\b\xE5\x92'rS \t\xC69\x02\x97K\nT\x8C-\f\xBDe\x9CaT\xEF\x90m\xC6Vb\xC8\x04\xD7k#\xD1\xB0\xC7\xE7\xE56\x96\x05\xF9F\x01\xC1\xAC\f\x96\x84\xAAl\x84X\xDE\xAD\xE72\x85,\xFD'\x1A\xDC9`\xBC^\r~\x1De\x7F!\xFA\xCD\xC30\xB3\xEE\x00\xC9\xF8\x1E\x0F\xB5g\x87\xA0\xAFF\xE3U\xFF\f\fc\x8E\xDB\xD9\x11\x9C\x17Z\x87\xB0\xF2QVb\x7F~dS\xAF\x04w\xFB\xEC\xA7\x96\x98\x93\x96\x109r\xF0D\xFAf\x7F\x00\xE0\xE9\x9F6\xBC\x81\x87.\xFBm\xC0\x9BR\xB2\x19\xA5\xBF\x8C\x0F3\x19\vA\xCE\xF5oo\xD7+\x04\xE0\xA7\xAD@2\x8D\xF3\xBE\x13\xC7\xC6!\xED#\x10\xC5\x1A\x9F\x82\x99b7q\xE4\xB8i\n\xA8\x88\xEB\xCB\xC0\x1C\xDFToLC\x90\x12\xCF)\xB0\xF1\xC9\xFDK^D\b%\x8DdE>\xBC~\xB1g\x80\xC39\x1E\xE8\xBF\xE0\x90p\xF8\x00\xCF\x18)\xABr\x01\fC\x02\v\x81{\x1A\xAC\xF5%3S\x86\xF5%\xEF\x7F\x1D\x1D\x05?\x128J?\x98\x03\xC8\x9F\xF3\x9B\x87\x80\xB2O\xCD==X\xB5">]>]>]>]>]>]>]>
=end
  let(:sample_tgs_req) do
    "\x6c\x82\x05\x30\x30\x82\x05\x2c\xa1\x03\x02\x01" +
    "\x05\xa2\x03\x02\x01\x0c\xa3\x82\x01\xfe\x30\x82\x01\xfa\x30\x82" +
    "\x01\xe3\xa1\x03\x02\x01\x01\xa2\x82\x01\xda\x04\x82\x01\xd6\x6e" +
    "\x82\x01\xd2\x30\x82\x01\xce\xa0\x03\x02\x01\x05\xa1\x03\x02\x01" +
    "\x0e\xa2\x07\x03\x05\x00\x00\x00\x00\x00\xa3\x82\x01\x10\x61\x82" +
    "\x01\x0c\x30\x82\x01\x08\xa0\x03\x02\x01\x05\xa1\x0c\x1b\x0a\x44" +
    "\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa2\x1f\x30\x1d\xa0\x03\x02" +
    "\x01\x01\xa1\x16\x30\x14\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\x0a" +
    "\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa3\x81\xd1\x30\x81\xce" +
    "\xa0\x03\x02\x01\x17\xa1\x03\x02\x01\x02\xa2\x81\xc1\x04\x81\xbe" +
    "\x55\xe7\x45\xc3\x6f\xa2\x28\x47\xab\x9c\x86\x13\xeb\x1d\xa8\x98" +
    "\xec\x67\x1c\x1f\x15\x46\x6b\xe0\x4a\xf2\x4d\x3d\xf7\xe4\x31\x7a" +
    "\x4f\x15\x2f\x60\xdd\x98\xa8\xe1\x97\x6b\x6f\xc1\x24\x46\x6c\xa9" +
    "\x1e\xe2\x36\x27\xe3\xfa\x99\x0c\x9b\x77\x0c\xe2\x58\x02\x68\xc4" +
    "\x54\x2a\x2c\x5d\x6c\x4b\xc8\xbc\x04\x8f\x0a\x44\x27\x78\xdc\x4b" +
    "\x3e\x01\xbe\xac\xf7\x8e\x7a\x50\xc6\x3e\x77\xd9\x65\x24\xd5\x1a" +
    "\x18\xa1\x84\x71\x85\x98\x2f\x54\x8b\x56\xe3\xfb\x2c\xe2\x30\x84" +
    "\x06\x55\x55\xea\x31\x8b\x84\x00\xe3\x1a\xc3\xa8\xc2\xac\xc0\x78" +
    "\x3f\x47\x68\x74\xcc\x62\xa6\xcf\xf4\x6b\xae\xaf\x27\xde\x1a\x4d" +
    "\xb7\xa8\x9f\x76\x7a\x79\x2a\x42\x12\x7b\xd2\xbe\xc9\x98\x7c\x44" +
    "\x38\x40\xbd\x49\xcd\x3e\xdc\x65\xc7\x8b\x44\xf5\xa5\xd4\x66\x0e" +
    "\xfd\x58\x9d\x31\x39\x27\xd7\xfc\x81\x07\xa3\x2a\x1c\x3c\xa4\x81" +
    "\xa4\x30\x81\xa1\xa0\x03\x02\x01\x17\xa2\x81\x99\x04\x81\x96\x6d" +
    "\xb5\xea\x35\x51\x26\x94\xf5\x31\x27\xd1\x00\x59\xed\x6c\xbc\x20" +
    "\x2c\x89\x70\x7a\x14\x74\xc9\x05\x85\x07\xf7\x36\x53\xcd\x80\x6a" +
    "\xa1\x62\xe6\x73\x3a\x7d\x71\x83\x1d\x93\xc6\x74\xc5\x6f\x7b\x71" +
    "\x1d\xce\xd3\x0b\x46\x8b\xc1\x13\x56\xe7\xee\x8c\xa2\xcc\xa6\x78" +
    "\xde\x7e\x80\x23\x39\x67\xd8\x2c\x3a\x6a\x12\x3e\x20\xc5\xaa\xd0" +
    "\xae\xd5\x5e\xb6\x7c\x83\x66\xfc\xc5\x65\x1e\xea\x62\x97\x48\x68" +
    "\xda\x8e\x62\x7c\x06\x35\x7d\xc5\x33\x25\xbc\x93\x8a\x64\x16\x2d" +
    "\xf4\xde\x7c\x56\xd0\x3b\x13\x4f\x2f\x86\x75\x14\x60\x80\x4d\x77" +
    "\xeb\x04\x08\xe6\x41\x20\xee\x16\x0f\xe2\x2b\x76\xd5\x14\x60\x2d" +
    "\xf6\xa8\xde\xf2\xb5\x30\x11\xa1\x04\x02\x02\x00\x80\xa2\x09\x04" +
    "\x07\x30\x05\xa0\x03\x01\x01\x00\xa4\x82\x03\x1c\x30\x82\x03\x18" +
    "\xa0\x07\x03\x05\x00\x50\x80\x00\x00\xa2\x0c\x1b\x0a\x44\x45\x4d" +
    "\x4f\x2e\x4c\x4f\x43\x41\x4c\xa3\x1f\x30\x1d\xa0\x03\x02\x01\x01" +
    "\xa1\x16\x30\x14\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\x0a\x44\x45" +
    "\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa4\x11\x18\x0f\x31\x39\x37\x30" +
    "\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a\xa5\x11\x18\x0f\x31" +
    "\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a\xa6\x11" +
    "\x18\x0f\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30" +
    "\x5a\xa7\x06\x02\x04\x7a\x5f\xfa\xac\xa8\x05\x30\x03\x02\x01\x17" +
    "\xaa\x82\x02\x94\x30\x82\x02\x90\xa0\x03\x02\x01\x17\xa2\x82\x02" +
    "\x87\x04\x82\x02\x83\x8a\x30\x9d\x7c\xa7\xe4\x22\x36\x0d\x44\xf5" +
    "\xd1\x3a\x00\x8b\x37\x6e\x52\x20\xbc\xea\x8b\x70\x66\xc0\x90\xc4" +
    "\x28\x27\x31\xcf\x16\x2c\x7c\x20\x7c\xaa\x3c\xe0\xc7\x6a\xfb\xb9" +
    "\x41\xb2\xd9\xa2\xd8\x59\x92\xb5\x82\x17\x8a\x93\x56\x51\x97\xf9" +
    "\xad\x1d\xc6\xc6\xbc\xa0\x44\x9b\xc5\xc1\xd8\x31\xf1\x94\x88\x37" +
    "\x0b\xa5\xaf\x51\xb0\x3d\x9a\x6d\xc0\xb2\xf1\x20\x33\xb7\x87\x7a" +
    "\xcf\xf7\xde\xa0\x8b\x83\xae\x76\x71\x38\x7d\x42\x4d\xde\x0a\x03" +
    "\xbe\xb7\x1c\xf4\x8c\x84\x16\x35\x2e\x60\xc4\x83\x17\x71\xe7\x00" +
    "\x23\xfb\xa1\x01\xd3\xda\xe0\x7f\xcd\x04\x3d\x53\x85\x4e\x72\x09" +
    "\x63\xf4\x06\xd8\x51\x15\xab\x15\xec\x4f\x80\xc5\xf3\xe2\x8a\x7f" +
    "\x97\x0f\x71\xed\x0c\xe9\x9f\x19\x14\x6b\x3d\x94\x4a\xae\x3e\xb8" +
    "\x1a\x33\xc4\x56\xcf\x36\xf8\x56\x0a\xe9\xaf\x5c\xb5\x42\x40\x72" +
    "\xde\xd5\x95\x37\xa0\xe5\x93\xc3\x32\xef\x82\x0a\x0f\x1e\x0a\x75" +
    "\x20\xb6\x8d\xfc\xe2\xce\xb3\x87\xdf\xa5\x04\x67\xf4\x30\x1a\x0a" +
    "\x19\x38\x46\x5a\x58\x46\xf4\x34\xba\xdb\x46\x4e\xc4\xcc\xaa\xbc" +
    "\x24\x85\xa5\x24\x84\x96\xa4\x75\x43\x46\x7f\x11\xce\x47\x9f\xfa" +
    "\x84\xce\xb6\x35\xcd\x95\x1e\x1d\x03\x88\x1d\xe3\x3a\x53\x9b\xa5" +
    "\x1b\x97\x83\xcf\xb3\x9e\x88\x08\x86\x6d\x48\x98\xec\x8d\x83\x42" +
    "\xae\xc9\x92\x56\xd5\xa9\x90\x03\x47\xb8\xd7\x81\xf4\x6e\x1e\x6d" +
    "\x73\x8a\x3a\xc6\x0f\xb1\x38\x99\x4f\x06\x04\x11\x7d\xa3\x39\x34" +
    "\xa9\x9e\x8e\x48\xcc\x64\xf3\x33\x3c\x0b\x88\x3e\x42\xf8\x74\x3e" +
    "\x92\x68\x67\x26\xeb\x46\xaa\xc8\x31\x77\x4b\xb1\x57\xef\x49\xd3" +
    "\x98\xf5\x53\xc0\x58\x19\x26\xb7\x1b\x8c\x17\x77\xbc\xe0\x20\xe9" +
    "\x80\x08\xe5\x92\x27\x72\x53\x20\x09\xc6\x39\x02\x97\x4b\x0a\x54" +
    "\x8c\x2d\x0c\xbd\x65\x9c\x61\x54\xef\x90\x6d\xc6\x56\x62\xc8\x04" +
    "\xd7\x6b\x23\xd1\xb0\xc7\xe7\xe5\x36\x96\x05\xf9\x46\x01\xc1\xac" +
    "\x0c\x96\x84\xaa\x6c\x84\x58\xde\xad\xe7\x32\x85\x2c\xfd\x27\x1a" +
    "\xdc\x39\x60\xbc\x5e\x0d\x7e\x1d\x65\x7f\x21\xfa\xcd\xc3\x30\xb3" +
    "\xee\x00\xc9\xf8\x1e\x0f\xb5\x67\x87\xa0\xaf\x46\xe3\x55\xff\x0c" +
    "\x0c\x63\x8e\xdb\xd9\x11\x9c\x17\x5a\x87\xb0\xf2\x51\x56\x62\x7f" +
    "\x7e\x64\x53\xaf\x04\x77\xfb\xec\xa7\x96\x98\x93\x96\x10\x39\x72" +
    "\xf0\x44\xfa\x66\x7f\x00\xe0\xe9\x9f\x36\xbc\x81\x87\x2e\xfb\x6d" +
    "\xc0\x9b\x52\xb2\x19\xa5\xbf\x8c\x0f\x33\x19\x0b\x41\xce\xf5\x6f" +
    "\x6f\xd7\x2b\x04\xe0\xa7\xad\x40\x32\x8d\xf3\xbe\x13\xc7\xc6\x21" +
    "\xed\x23\x10\xc5\x1a\x9f\x82\x99\x62\x37\x71\xe4\xb8\x69\x0a\xa8" +
    "\x88\xeb\xcb\xc0\x1c\xdf\x54\x6f\x4c\x43\x90\x12\xcf\x29\xb0\xf1" +
    "\xc9\xfd\x4b\x5e\x44\x08\x25\x8d\x64\x45\x3e\xbc\x7e\xb1\x67\x80" +
    "\xc3\x39\x1e\xe8\xbf\xe0\x90\x70\xf8\x00\xcf\x18\x29\xab\x72\x01" +
    "\x0c\x43\x02\x0b\x81\x7b\x1a\xac\xf5\x25\x33\x53\x86\xf5\x25\xef" +
    "\x7f\x1d\x1d\x05\x3f\x12\x38\x4a\x3f\x98\x03\xc8\x9f\xf3\x9b\x87" +
    "\x80\xb2\x4f\xcd\x3d\x3d\x58\xb5"
  end

  describe "#decode" do
    context "when AS-REQ" do
      it "returns the Rex::Proto::Kerberos::Model::KdcRequest decoded" do
        expect(kdc_request.decode(sample_as_req)).to eq(kdc_request)
      end

      it "decodes msg_type correctly" do
        kdc_request.decode(sample_as_req)
        expect(kdc_request.msg_type).to eq(as_req)
      end

      it "decodes pvno correctly" do
        kdc_request.decode(sample_as_req)
        expect(kdc_request.pvno).to eq(5)
      end

      it "decodes req_body correctly" do
        kdc_request.decode(sample_as_req)
        expect(kdc_request.req_body.cname.name_string).to eq(['juan'])
      end

      it "decodes pa_data correctly" do
        kdc_request.decode(sample_as_req)
        expect(kdc_request.pa_data.length).to eq(2)
      end

      it "decodes PA-ENC-TIMESTAMP type correctly" do
        kdc_request.decode(sample_as_req)
        expect(kdc_request.pa_data[0].type).to eq(2)
      end

      it "decodes PA-PAC-REQUEST type correctly" do
        kdc_request.decode(sample_as_req)
        expect(kdc_request.pa_data[1].type).to eq(128)
      end
    end

    context "when TGS-REQ" do
      it "returns the Rex::Proto::Kerberos::Model::KdcRequest decoded" do
        expect(kdc_request.decode(sample_tgs_req)).to eq(kdc_request)
      end

      it "decodes msg_type correctly" do
        kdc_request.decode(sample_tgs_req)
        expect(kdc_request.msg_type).to eq(tgs_req)
      end

      it "decodes pvno correctly" do
        kdc_request.decode(sample_tgs_req)
        expect(kdc_request.pvno).to eq(5)
      end

      it "decodes req_body correctly" do
        kdc_request.decode(sample_tgs_req)
        expect(kdc_request.req_body.sname.name_string).to eq(["krbtgt", "DEMO.LOCAL"])
      end

      it "decodes pa_data correctly" do
        kdc_request.decode(sample_tgs_req)
        expect(kdc_request.pa_data.length).to eq(2)
      end

      it "decodes PA-TGS-REQ type correctly" do
        kdc_request.decode(sample_tgs_req)
        expect(kdc_request.pa_data[0].type).to eq(1)
      end

      it "decodes PA-PAC-REQUEST type correctly" do
        kdc_request.decode(sample_tgs_req)
        expect(kdc_request.pa_data[1].type).to eq(128)
      end

    end
  end

  describe "#encode" do
    context "when AS-REQ" do
      it "re-encodes a KdcRequest correctly" do
        kdc_request.decode(sample_as_req)
        expect(kdc_request.encode).to eq(sample_as_req)
      end
    end

    context "when TGS-REQ" do
      it "re-encodes a KdcRequest correctly" do
        kdc_request.decode(sample_tgs_req)
        expect(kdc_request.encode).to eq(sample_tgs_req)
      end
    end
  end

end
