# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::KdcRequestBody do

  subject(:kdc_request_body) do
    described_class.new
  end

=begin
#<OpenSSL::ASN1::Sequence:0x007ff9c30196d0
 @infinite_length=false,
 @tag=16,
 @tag_class=:UNIVERSAL,
 @tagging=nil,
 @value=
  [#<OpenSSL::ASN1::ASN1Data:0x007ff9c301bb60
    @infinite_length=false,
    @tag=0,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::BitString:0x007ff9c301bbb0
       @infinite_length=false,
       @tag=3,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @unused_bits=0,
       @value="P\x80\x00\x00">]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c301b570
    @infinite_length=false,
    @tag=1,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Sequence:0x007ff9c301b5e8
       @infinite_length=false,
       @tag=16,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=
        [#<OpenSSL::ASN1::ASN1Data:0x007ff9c301b7f0
          @infinite_length=false,
          @tag=0,
          @tag_class=:CONTEXT_SPECIFIC,
          @value=
           [#<OpenSSL::ASN1::Integer:0x007ff9c301b818
             @infinite_length=false,
             @tag=2,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=#<OpenSSL::BN:0x007ff9c301b840>>]>,
         #<OpenSSL::ASN1::ASN1Data:0x007ff9c301b610
          @infinite_length=false,
          @tag=1,
          @tag_class=:CONTEXT_SPECIFIC,
          @value=
           [#<OpenSSL::ASN1::Sequence:0x007ff9c301b660
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::GeneralString:0x007ff9c301b688
                @infinite_length=false,
                @tag=27,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value="juan">]>]>]>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c301b318
    @infinite_length=false,
    @tag=2,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralString:0x007ff9c301b408
       @infinite_length=false,
       @tag=27,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value="DEMO.LOCAL">]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c301a760
    @infinite_length=false,
    @tag=3,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Sequence:0x007ff9c301a7b0
       @infinite_length=false,
       @tag=16,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=
        [#<OpenSSL::ASN1::ASN1Data:0x007ff9c301ab20
          @infinite_length=false,
          @tag=0,
          @tag_class=:CONTEXT_SPECIFIC,
          @value=
           [#<OpenSSL::ASN1::Integer:0x007ff9c301ab98
             @infinite_length=false,
             @tag=2,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=#<OpenSSL::BN:0x007ff9c301abc0>>]>,
         #<OpenSSL::ASN1::ASN1Data:0x007ff9c301a800
          @infinite_length=false,
          @tag=1,
          @tag_class=:CONTEXT_SPECIFIC,
          @value=
           [#<OpenSSL::ASN1::Sequence:0x007ff9c301a828
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::GeneralString:0x007ff9c301aa08
                @infinite_length=false,
                @tag=27,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value="krbtgt">,
               #<OpenSSL::ASN1::GeneralString:0x007ff9c301a850
                @infinite_length=false,
                @tag=27,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value="DEMO.LOCAL">]>]>]>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c301a2d8
    @infinite_length=false,
    @tag=4,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c301a3a0
       @infinite_length=false,
       @tag=24,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=1970-01-01 00:00:00 UTC>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c3019f68
    @infinite_length=false,
    @tag=5,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c3019f90
       @infinite_length=false,
       @tag=24,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=1970-01-01 00:00:00 UTC>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c3019ba8
    @infinite_length=false,
    @tag=6,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c3019bf8
       @infinite_length=false,
       @tag=24,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=1970-01-01 00:00:00 UTC>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c3019978
    @infinite_length=false,
    @tag=7,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Integer:0x007ff9c3019a68
       @infinite_length=false,
       @tag=2,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=#<OpenSSL::BN:0x007ff9c3019a90>>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c30196f8
    @infinite_length=false,
    @tag=8,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Sequence:0x007ff9c3019798
       @infinite_length=false,
       @tag=16,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff9c3019838
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff9c30198d8>>]>]>]>
=end
  let(:sample_as_req) do
    "\x30\x81\x93\xa0\x07\x03\x05\x00" +
    "\x50\x80\x00\x00\xa1\x11\x30\x0f" +
    "\xa0\x03\x02\x01\x01\xa1\x08\x30" +
    "\x06\x1b\x04\x6a\x75\x61\x6e\xa2" +
    "\x0c\x1b\x0a\x44\x45\x4d\x4f\x2e" +
    "\x4c\x4f\x43\x41\x4c\xa3\x1f\x30" +
    "\x1d\xa0\x03\x02\x01\x01\xa1\x16" +
    "\x30\x14\x1b\x06\x6b\x72\x62\x74" +
    "\x67\x74\x1b\x0a\x44\x45\x4d\x4f" +
    "\x2e\x4c\x4f\x43\x41\x4c\xa4\x11" +
    "\x18\x0f\x31\x39\x37\x30\x30\x31" +
    "\x30\x31\x30\x30\x30\x30\x30\x30" +
    "\x5a\xa5\x11\x18\x0f\x31\x39\x37" +
    "\x30\x30\x31\x30\x31\x30\x30\x30" +
    "\x30\x30\x30\x5a\xa6\x11\x18\x0f" +
    "\x31\x39\x37\x30\x30\x31\x30\x31" +
    "\x30\x30\x30\x30\x30\x30\x5a\xa7" +
    "\x06\x02\x04\x18\xf4\x10\x2c\xa8" +
    "\x05\x30\x03\x02\x01\x17"
  end

=begin
#<OpenSSL::ASN1::Sequence:0x007ff9c387ab80
 @infinite_length=false,
 @tag=16,
 @tag_class=:UNIVERSAL,
 @tagging=nil,
 @value=
  [#<OpenSSL::ASN1::ASN1Data:0x007ff9c387b580
    @infinite_length=false,
    @tag=0,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::BitString:0x007ff9c387b5a8
       @infinite_length=false,
       @tag=3,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @unused_bits=0,
       @value="P\x80\x00\x00">]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c387b4e0
    @infinite_length=false,
    @tag=2,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralString:0x007ff9c387b508
       @infinite_length=false,
       @tag=27,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value="DEMO.LOCAL">]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c387b260
    @infinite_length=false,
    @tag=3,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Sequence:0x007ff9c387b288
       @infinite_length=false,
       @tag=16,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=
        [#<OpenSSL::ASN1::ASN1Data:0x007ff9c387b3f0
          @infinite_length=false,
          @tag=0,
          @tag_class=:CONTEXT_SPECIFIC,
          @value=
           [#<OpenSSL::ASN1::Integer:0x007ff9c387b418
             @infinite_length=false,
             @tag=2,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=#<OpenSSL::BN:0x007ff9c387b440>>]>,
         #<OpenSSL::ASN1::ASN1Data:0x007ff9c387b2b0
          @infinite_length=false,
          @tag=1,
          @tag_class=:CONTEXT_SPECIFIC,
          @value=
           [#<OpenSSL::ASN1::Sequence:0x007ff9c387b2d8
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::GeneralString:0x007ff9c387b350
                @infinite_length=false,
                @tag=27,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value="krbtgt">,
               #<OpenSSL::ASN1::GeneralString:0x007ff9c387b300
                @infinite_length=false,
                @tag=27,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value="DEMO.LOCAL">]>]>]>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c387b148
    @infinite_length=false,
    @tag=4,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c387b170
       @infinite_length=false,
       @tag=24,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=1970-01-01 00:00:00 UTC>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c387b030
    @infinite_length=false,
    @tag=5,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c387b058
       @infinite_length=false,
       @tag=24,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=1970-01-01 00:00:00 UTC>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c387af18
    @infinite_length=false,
    @tag=6,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::GeneralizedTime:0x007ff9c387af40
       @infinite_length=false,
       @tag=24,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=1970-01-01 00:00:00 UTC>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c387ae78
    @infinite_length=false,
    @tag=7,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Integer:0x007ff9c387aea0
       @infinite_length=false,
       @tag=2,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=#<OpenSSL::BN:0x007ff9c387aec8>>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c387ad88
    @infinite_length=false,
    @tag=8,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Sequence:0x007ff9c387adb0
       @infinite_length=false,
       @tag=16,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff9c387add8
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff9c387ae00>>]>]>,
   #<OpenSSL::ASN1::ASN1Data:0x007ff9c387aba8
    @infinite_length=false,
    @tag=10,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Sequence:0x007ff9c387abd0
       @infinite_length=false,
       @tag=16,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=
        [#<OpenSSL::ASN1::ASN1Data:0x007ff9c387ac98
          @infinite_length=false,
          @tag=0,
          @tag_class=:CONTEXT_SPECIFIC,
          @value=
           [#<OpenSSL::ASN1::Integer:0x007ff9c387acc0
             @infinite_length=false,
             @tag=2,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=#<OpenSSL::BN:0x007ff9c387ace8>>]>,
         #<OpenSSL::ASN1::ASN1Data:0x007ff9c387abf8
          @infinite_length=false,
          @tag=2,
          @tag_class=:CONTEXT_SPECIFIC,
          @value=
           [#<OpenSSL::ASN1::OctetString:0x007ff9c387ac20
             @infinite_length=false,
             @tag=4,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              "\x8A0\x9D|\xA7\xE4\"6\rD\xF5\xD1:\x00\x8B7nR \xBC\xEA\x8Bpf\xC0\x90\xC4('1\xCF\x16,| |\xAA<\xE0\xC7j\xFB\xB9A\xB2\xD9\xA2\xD8Y\x92\xB5\x82\x17\x8A\x93VQ\x97\xF9\xAD\x1D\xC6\xC6\xBC\xA0D\x9B\xC5\xC1\xD81\xF1\x94\x887\v\xA5\xAFQ\xB0=\x9Am\xC0\xB2\xF1 3\xB7\x87z\xCF\xF7\xDE\xA0\x8B\x83\xAEvq8}BM\xDE\n\x03\xBE\xB7\x1C\xF4\x8C\x84\x165.`\xC4\x83\x17q\xE7\x00#\xFB\xA1\x01\xD3\xDA\xE0\x7F\xCD\x04=S\x85Nr\tc\xF4\x06\xD8Q\x15\xAB\x15\xECO\x80\xC5\xF3\xE2\x8A\x7F\x97\x0Fq\xED\f\xE9\x9F\x19\x14k=\x94J\xAE>\xB8\x1A3\xC4V\xCF6\xF8V\n\xE9\xAF\\\xB5B@r\xDE\xD5\x957\xA0\xE5\x93\xC32\xEF\x82\n\x0F\x1E\nu \xB6\x8D\xFC\xE2\xCE\xB3\x87\xDF\xA5\x04g\xF40\x1A\n\x198FZXF\xF44\xBA\xDBFN\xC4\xCC\xAA\xBC$\x85\xA5$\x84\x96\xA4uCF\x7F\x11\xCEG\x9F\xFA\x84\xCE\xB65\xCD\x95\x1E\x1D\x03\x88\x1D\xE3:S\x9B\xA5\e\x97\x83\xCF\xB3\x9E\x88\b\x86mH\x98\xEC\x8D\x83B\xAE\xC9\x92V\xD5\xA9\x90\x03G\xB8\xD7\x81\xF4n\x1Ems\x8A:\xC6\x0F\xB18\x99O\x06\x04\x11}\xA394\xA9\x9E\x8EH\xCCd\xF33<\v\x88>B\xF8t>\x92hg&\xEBF\xAA\xC81wK\xB1W\xEFI\xD3\x98\xF5S\xC0X\x19&\xB7\e\x8C\x17w\xBC\xE0 \xE9\x80\b\xE5\x92'rS \t\xC69\x02\x97K\nT\x8C-\f\xBDe\x9CaT\xEF\x90m\xC6Vb\xC8\x04\xD7k#\xD1\xB0\xC7\xE7\xE56\x96\x05\xF9F\x01\xC1\xAC\f\x96\x84\xAAl\x84X\xDE\xAD\xE72\x85,\xFD'\x1A\xDC9`\xBC^\r~\x1De\x7F!\xFA\xCD\xC30\xB3\xEE\x00\xC9\xF8\x1E\x0F\xB5g\x87\xA0\xAFF\xE3U\xFF\f\fc\x8E\xDB\xD9\x11\x9C\x17Z\x87\xB0\xF2QVb\x7F~dS\xAF\x04w\xFB\xEC\xA7\x96\x98\x93\x96\x109r\xF0D\xFAf\x7F\x00\xE0\xE9\x9F6\xBC\x81\x87.\xFBm\xC0\x9BR\xB2\x19\xA5\xBF\x8C\x0F3\x19\vA\xCE\xF5oo\xD7+\x04\xE0\xA7\xAD@2\x8D\xF3\xBE\x13\xC7\xC6!\xED#\x10\xC5\x1A\x9F\x82\x99b7q\xE4\xB8i\n\xA8\x88\xEB\xCB\xC0\x1C\xDFToLC\x90\x12\xCF)\xB0\xF1\xC9\xFDK^D\b%\x8DdE>\xBC~\xB1g\x80\xC39\x1E\xE8\xBF\xE0\x90p\xF8\x00\xCF\x18)\xABr\x01\fC\x02\v\x81{\x1A\xAC\xF5%3S\x86\xF5%\xEF\x7F\x1D\x1D\x05?\x128J?\x98\x03\xC8\x9F\xF3\x9B\x87\x80\xB2O\xCD==X\xB5">]>]>]>]>
=end
  let(:sample_tgs_req) do
    "\x30\x82\x03\x18\xa0\x07\x03\x05\x00\x50\x80\x00\x00\xa2\x0c\x1b" +
    "\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa3\x1f\x30\x1d\xa0" +
    "\x03\x02\x01\x01\xa1\x16\x30\x14\x1b\x06\x6b\x72\x62\x74\x67\x74" +
    "\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa4\x11\x18\x0f" +
    "\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30\x30\x5a\xa5" +
    "\x11\x18\x0f\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30\x30\x30\x30" +
    "\x30\x5a\xa6\x11\x18\x0f\x31\x39\x37\x30\x30\x31\x30\x31\x30\x30" +
    "\x30\x30\x30\x30\x5a\xa7\x06\x02\x04\x7a\x5f\xfa\xac\xa8\x05\x30" +
    "\x03\x02\x01\x17\xaa\x82\x02\x94\x30\x82\x02\x90\xa0\x03\x02\x01" +
    "\x17\xa2\x82\x02\x87\x04\x82\x02\x83\x8a\x30\x9d\x7c\xa7\xe4\x22" +
    "\x36\x0d\x44\xf5\xd1\x3a\x00\x8b\x37\x6e\x52\x20\xbc\xea\x8b\x70" +
    "\x66\xc0\x90\xc4\x28\x27\x31\xcf\x16\x2c\x7c\x20\x7c\xaa\x3c\xe0" +
    "\xc7\x6a\xfb\xb9\x41\xb2\xd9\xa2\xd8\x59\x92\xb5\x82\x17\x8a\x93" +
    "\x56\x51\x97\xf9\xad\x1d\xc6\xc6\xbc\xa0\x44\x9b\xc5\xc1\xd8\x31" +
    "\xf1\x94\x88\x37\x0b\xa5\xaf\x51\xb0\x3d\x9a\x6d\xc0\xb2\xf1\x20" +
    "\x33\xb7\x87\x7a\xcf\xf7\xde\xa0\x8b\x83\xae\x76\x71\x38\x7d\x42" +
    "\x4d\xde\x0a\x03\xbe\xb7\x1c\xf4\x8c\x84\x16\x35\x2e\x60\xc4\x83" +
    "\x17\x71\xe7\x00\x23\xfb\xa1\x01\xd3\xda\xe0\x7f\xcd\x04\x3d\x53" +
    "\x85\x4e\x72\x09\x63\xf4\x06\xd8\x51\x15\xab\x15\xec\x4f\x80\xc5" +
    "\xf3\xe2\x8a\x7f\x97\x0f\x71\xed\x0c\xe9\x9f\x19\x14\x6b\x3d\x94" +
    "\x4a\xae\x3e\xb8\x1a\x33\xc4\x56\xcf\x36\xf8\x56\x0a\xe9\xaf\x5c" +
    "\xb5\x42\x40\x72\xde\xd5\x95\x37\xa0\xe5\x93\xc3\x32\xef\x82\x0a" +
    "\x0f\x1e\x0a\x75\x20\xb6\x8d\xfc\xe2\xce\xb3\x87\xdf\xa5\x04\x67" +
    "\xf4\x30\x1a\x0a\x19\x38\x46\x5a\x58\x46\xf4\x34\xba\xdb\x46\x4e" +
    "\xc4\xcc\xaa\xbc\x24\x85\xa5\x24\x84\x96\xa4\x75\x43\x46\x7f\x11" +
    "\xce\x47\x9f\xfa\x84\xce\xb6\x35\xcd\x95\x1e\x1d\x03\x88\x1d\xe3" +
    "\x3a\x53\x9b\xa5\x1b\x97\x83\xcf\xb3\x9e\x88\x08\x86\x6d\x48\x98" +
    "\xec\x8d\x83\x42\xae\xc9\x92\x56\xd5\xa9\x90\x03\x47\xb8\xd7\x81" +
    "\xf4\x6e\x1e\x6d\x73\x8a\x3a\xc6\x0f\xb1\x38\x99\x4f\x06\x04\x11" +
    "\x7d\xa3\x39\x34\xa9\x9e\x8e\x48\xcc\x64\xf3\x33\x3c\x0b\x88\x3e" +
    "\x42\xf8\x74\x3e\x92\x68\x67\x26\xeb\x46\xaa\xc8\x31\x77\x4b\xb1" +
    "\x57\xef\x49\xd3\x98\xf5\x53\xc0\x58\x19\x26\xb7\x1b\x8c\x17\x77" +
    "\xbc\xe0\x20\xe9\x80\x08\xe5\x92\x27\x72\x53\x20\x09\xc6\x39\x02" +
    "\x97\x4b\x0a\x54\x8c\x2d\x0c\xbd\x65\x9c\x61\x54\xef\x90\x6d\xc6" +
    "\x56\x62\xc8\x04\xd7\x6b\x23\xd1\xb0\xc7\xe7\xe5\x36\x96\x05\xf9" +
    "\x46\x01\xc1\xac\x0c\x96\x84\xaa\x6c\x84\x58\xde\xad\xe7\x32\x85" +
    "\x2c\xfd\x27\x1a\xdc\x39\x60\xbc\x5e\x0d\x7e\x1d\x65\x7f\x21\xfa" +
    "\xcd\xc3\x30\xb3\xee\x00\xc9\xf8\x1e\x0f\xb5\x67\x87\xa0\xaf\x46" +
    "\xe3\x55\xff\x0c\x0c\x63\x8e\xdb\xd9\x11\x9c\x17\x5a\x87\xb0\xf2" +
    "\x51\x56\x62\x7f\x7e\x64\x53\xaf\x04\x77\xfb\xec\xa7\x96\x98\x93" +
    "\x96\x10\x39\x72\xf0\x44\xfa\x66\x7f\x00\xe0\xe9\x9f\x36\xbc\x81" +
    "\x87\x2e\xfb\x6d\xc0\x9b\x52\xb2\x19\xa5\xbf\x8c\x0f\x33\x19\x0b" +
    "\x41\xce\xf5\x6f\x6f\xd7\x2b\x04\xe0\xa7\xad\x40\x32\x8d\xf3\xbe" +
    "\x13\xc7\xc6\x21\xed\x23\x10\xc5\x1a\x9f\x82\x99\x62\x37\x71\xe4" +
    "\xb8\x69\x0a\xa8\x88\xeb\xcb\xc0\x1c\xdf\x54\x6f\x4c\x43\x90\x12" +
    "\xcf\x29\xb0\xf1\xc9\xfd\x4b\x5e\x44\x08\x25\x8d\x64\x45\x3e\xbc" +
    "\x7e\xb1\x67\x80\xc3\x39\x1e\xe8\xbf\xe0\x90\x70\xf8\x00\xcf\x18" +
    "\x29\xab\x72\x01\x0c\x43\x02\x0b\x81\x7b\x1a\xac\xf5\x25\x33\x53" +
    "\x86\xf5\x25\xef\x7f\x1d\x1d\x05\x3f\x12\x38\x4a\x3f\x98\x03\xc8" +
    "\x9f\xf3\x9b\x87\x80\xb2\x4f\xcd\x3d\x3d\x58\xb5"
  end

  describe "#decode" do
    context "when KdcRequestBody from a KRB_AS_REQ message" do
      it "returns the KdcRequestBody instance" do
        expect(kdc_request_body.decode(sample_as_req)).to eq(kdc_request_body)
      end

      it "decodes options" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.options).to eq(0x50800000)
      end

      it "decodes cname" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.cname.name_string).to eq(['juan'])
      end

      it "decodes realm" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.realm).to eq('DEMO.LOCAL')
      end

      it "decodes sname" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.sname.name_string).to eq(['krbtgt', 'DEMO.LOCAL'])
      end

      it "decodes from" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.from.to_s).to eq('1970-01-01 00:00:00 UTC')
      end

      it "decodes till" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.till.to_s).to eq('1970-01-01 00:00:00 UTC')
      end

      it "decodes rtime" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.rtime.to_s).to eq('1970-01-01 00:00:00 UTC')
      end

      it "decodes nonce" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.nonce).to eq(418648108)
      end

      it "decodes etype" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.etype).to eq([Rex::Proto::Kerberos::Crypto::RC4_HMAC])
      end

      it "doesn't decode enc_auth_data" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.enc_auth_data).to be_nil
      end

    end

    context "when KdcRequestBody from a KRB_TGS_REQ message" do
      it "returns the KdcRequestBody instance" do
        expect(kdc_request_body.decode(sample_tgs_req)).to eq(kdc_request_body)
      end

      it "decodes options" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.options).to eq(0x50800000)
      end

      it "leaves cname as nil" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.cname).to be_nil
      end

      it "decodes realm" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.realm).to eq('DEMO.LOCAL')
      end

      it "decodes sname" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.sname.name_string).to eq(['krbtgt', 'DEMO.LOCAL'])
      end

      it "decodes from" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.from.to_s).to eq('1970-01-01 00:00:00 UTC')
      end

      it "decodes till" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.till.to_s).to eq('1970-01-01 00:00:00 UTC')
      end

      it "decodes rtime" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.rtime.to_s).to eq('1970-01-01 00:00:00 UTC')
      end

      it "decodes nonce" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.nonce).to eq(2053110444)
      end

      it "decodes etype" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.etype).to eq([Rex::Proto::Kerberos::Crypto::RC4_HMAC])
      end

      it "decodes enc_auth_data" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.enc_auth_data.cipher.length).to eq(643)
      end
    end
  end

  describe "#encode" do
    context "when KdcRequestBody from a KRB_AS_REQ message" do
      it "encodes KdcRequestBody correctly" do
        kdc_request_body.decode(sample_as_req)
        expect(kdc_request_body.encode).to eq(sample_as_req)
      end
    end

    context "when KdcRequestBody from a KRB_TGS_REQ message" do
      it "encodes KdcRequestBody correctly" do
        kdc_request_body.decode(sample_tgs_req)
        expect(kdc_request_body.encode).to eq(sample_tgs_req)
      end
    end
  end
end
