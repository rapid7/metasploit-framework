# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::ApReq do

  subject(:ap_req) do
    described_class.new
  end

=begin
#<OpenSSL::ASN1::ASN1Data:0x007fe55b898350
 @infinite_length=false,
 @tag=14,
 @tag_class=:APPLICATION,
 @value=
  [#<OpenSSL::ASN1::Sequence:0x007fe55b8983a0
    @infinite_length=false,
    @tag=16,
    @tag_class=:UNIVERSAL,
    @tagging=nil,
    @value=
     [#<OpenSSL::ASN1::ASN1Data:0x007fe55b89a718
       @infinite_length=false,
       @tag=0,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007fe55b89a740
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007fe55b89a790>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fe55b89a650
       @infinite_length=false,
       @tag=1,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007fe55b89a678
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007fe55b89a6a0>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fe55b89a448
       @infinite_length=false,
       @tag=2,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::BitString:0x007fe55b89a4c0
          @infinite_length=false,
          @tag=3,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @unused_bits=0,
          @value="\x00\x00\x00\x00">]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fe55b898940
       @infinite_length=false,
       @tag=3,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::ASN1Data:0x007fe55b8989e0
          @infinite_length=false,
          @tag=1,
          @tag_class=:APPLICATION,
          @value=
           [#<OpenSSL::ASN1::Sequence:0x007fe55b898a58
             @infinite_length=false,
             @tag=16,
             @tag_class=:UNIVERSAL,
             @tagging=nil,
             @value=
              [#<OpenSSL::ASN1::ASN1Data:0x007fe55b899e30
                @infinite_length=false,
                @tag=0,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Integer:0x007fe55b899fe8
                   @infinite_length=false,
                   @tag=2,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=#<OpenSSL::BN:0x007fe55b89a088>>]>,
               #<OpenSSL::ASN1::ASN1Data:0x007fe55b899c78
                @infinite_length=false,
                @tag=1,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::GeneralString:0x007fe55b899ca0
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="DEMO.LOCAL">]>,
               #<OpenSSL::ASN1::ASN1Data:0x007fe55b899250
                @infinite_length=false,
                @tag=2,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Sequence:0x007fe55b8992a0
                   @infinite_length=false,
                   @tag=16,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=
                    [#<OpenSSL::ASN1::ASN1Data:0x007fe55b8998b8
                      @infinite_length=false,
                      @tag=0,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::Integer:0x007fe55b8998e0
                         @infinite_length=false,
                         @tag=2,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=#<OpenSSL::BN:0x007fe55b899930>>]>,
                     #<OpenSSL::ASN1::ASN1Data:0x007fe55b8992f0
                      @infinite_length=false,
                      @tag=1,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::Sequence:0x007fe55b899408
                         @infinite_length=false,
                         @tag=16,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=
                          [#<OpenSSL::ASN1::GeneralString:0x007fe55b8996d8
                            @infinite_length=false,
                            @tag=27,
                            @tag_class=:UNIVERSAL,
                            @tagging=nil,
                            @value="krbtgt">,
                           #<OpenSSL::ASN1::GeneralString:0x007fe55b899458
                            @infinite_length=false,
                            @tag=27,
                            @tag_class=:UNIVERSAL,
                            @tagging=nil,
                            @value="DEMO.LOCAL">]>]>]>]>,
               #<OpenSSL::ASN1::ASN1Data:0x007fe55b898af8
                @infinite_length=false,
                @tag=3,
                @tag_class=:CONTEXT_SPECIFIC,
                @value=
                 [#<OpenSSL::ASN1::Sequence:0x007fe55b898b48
                   @infinite_length=false,
                   @tag=16,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value=
                    [#<OpenSSL::ASN1::ASN1Data:0x007fe55b899048
                      @infinite_length=false,
                      @tag=0,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::Integer:0x007fe55b899098
                         @infinite_length=false,
                         @tag=2,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=#<OpenSSL::BN:0x007fe55b8990c0>>]>,
                     #<OpenSSL::ASN1::ASN1Data:0x007fe55b898df0
                      @infinite_length=false,
                      @tag=1,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::Integer:0x007fe55b898e90
                         @infinite_length=false,
                         @tag=2,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=#<OpenSSL::BN:0x007fe55b898f80>>]>,
                     #<OpenSSL::ASN1::ASN1Data:0x007fe55b898c88
                      @infinite_length=false,
                      @tag=2,
                      @tag_class=:CONTEXT_SPECIFIC,
                      @value=
                       [#<OpenSSL::ASN1::OctetString:0x007fe55b898cb0
                         @infinite_length=false,
                         @tag=4,
                         @tag_class=:UNIVERSAL,
                         @tagging=nil,
                         @value=
                          "\x81O\x84\xF4!\x93\xE5J\xCC%\x89S\xB3\xEEG\xF13\xDD\x15\xDCf\x05\x90\xE7g\x90\x1D\xBE\x03\xAAF\x02\xD0&M\e\xBB\x1F\t\xD4\xDCE\xBB\xA0|\xD0\xF2C\x9F\xAByL\x8F6\x9E\fXa\xC7\xAD`\xB2D1\xFE\x89@%\xFB\x8Bqi\"\x87\xABnQ\x8E:\xEDd\x16:\x7FM\xB6\xA1\xC8i\xD0\x12_\x01\xD8!8)\xE2\x97cZM\xBF\xC9\xD7\xE9\xC4\a(\x89\xDD\xC1a\xBA\xCC\x12r(\ep=\x1F\xAEP\xD5\x88[\xCA\x00U\xD8\xE9\xDD\x1C\x91~e\x99M\x97l\xB8\xC5\x89\xE1\xAFL\xE4\xB6:y\\\xCE\xF4\xA93y_i\xB9\x16\xBA\x12\x03)\xB1\x80\x89!\x1A\x93\xCD\xE7:\xBA\xCAW\x94G:i\x1A\x1A\x9D\x1D*\x1D6\x82\xFE">]>]>]>]>]>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fe55b8983f0
       @infinite_length=false,
       @tag=4,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007fe55b898468
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007fe55b898738
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007fe55b898760
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007fe55b898788>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007fe55b8984e0
             @infinite_length=false,
             @tag=2,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::OctetString:0x007fe55b898580
                @infinite_length=false,
                @tag=4,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 "+\xEA\x95|&\x13\x06%!\x8D\xF7\xCD\x0F[\xAC\xC8O5\xDB\xAD\x13\xC9\xFB\xF7\x0F\n \xCD|\xB7\xC0\xD1\x8C\xB6\x8D\x0F\x81\x88\xCE\xC2\xF1\xCB\xE3\xC1\x02=\t~M\xB8?\x0E\x8B(x\x90wh\x81\xE3\xC4\x88z\x84\xE8\x06\x82\x9D\xB95\xBA\xC1 \x8Cz\x93\xFE\xD1\x16\xE5\xC54~I\xC5\x9B\x80ZR7\xCEVO\x9DG8\xE9r\xB27\x01\x0F\xDF\x90\x8F\x14\xCA\xCE\x94\x10\xD9\x0E\x86\b\xE9\xA3=\x16j\x8AQ\x00j0z=Nen\x82\xA1\xE6Y\xD4\xBB\x95\\\xBC\xC86\xE1\x95\xCA~A<f\xC4\xDCA">]>]>]>]>]>
=end
  let(:sample) do
    "\x6e\x82\x01\xd2\x30\x82\x01\xce\xa0\x03\x02\x01\x05\xa1\x03\x02\x01\x0e\xa2\x07" +
    "\x03\x05\x00\x00\x00\x00\x00\xa3\x82\x01\x10\x61\x82\x01\x0c\x30\x82\x01\x08\xa0" +
    "\x03\x02\x01\x05\xa1\x0c\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa2\x1f" +
    "\x30\x1d\xa0\x03\x02\x01\x01\xa1\x16\x30\x14\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b" +
    "\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa3\x81\xd1\x30\x81\xce\xa0\x03\x02" +
    "\x01\x17\xa1\x03\x02\x01\x02\xa2\x81\xc1\x04\x81\xbe\x81\x4f\x84\xf4\x21\x93\xe5" +
    "\x4a\xcc\x25\x89\x53\xb3\xee\x47\xf1\x33\xdd\x15\xdc\x66\x05\x90\xe7\x67\x90\x1d" +
    "\xbe\x03\xaa\x46\x02\xd0\x26\x4d\x1b\xbb\x1f\x09\xd4\xdc\x45\xbb\xa0\x7c\xd0\xf2" +
    "\x43\x9f\xab\x79\x4c\x8f\x36\x9e\x0c\x58\x61\xc7\xad\x60\xb2\x44\x31\xfe\x89\x40" +
    "\x25\xfb\x8b\x71\x69\x22\x87\xab\x6e\x51\x8e\x3a\xed\x64\x16\x3a\x7f\x4d\xb6\xa1" +
    "\xc8\x69\xd0\x12\x5f\x01\xd8\x21\x38\x29\xe2\x97\x63\x5a\x4d\xbf\xc9\xd7\xe9\xc4" +
    "\x07\x28\x89\xdd\xc1\x61\xba\xcc\x12\x72\x28\x1b\x70\x3d\x1f\xae\x50\xd5\x88\x5b" +
    "\xca\x00\x55\xd8\xe9\xdd\x1c\x91\x7e\x65\x99\x4d\x97\x6c\xb8\xc5\x89\xe1\xaf\x4c" +
    "\xe4\xb6\x3a\x79\x5c\xce\xf4\xa9\x33\x79\x5f\x69\xb9\x16\xba\x12\x03\x29\xb1\x80" +
    "\x89\x21\x1a\x93\xcd\xe7\x3a\xba\xca\x57\x94\x47\x3a\x69\x1a\x1a\x9d\x1d\x2a\x1d" +
    "\x36\x82\xfe\xa4\x81\xa4\x30\x81\xa1\xa0\x03\x02\x01\x17\xa2\x81\x99\x04\x81\x96" +
    "\x2b\xea\x95\x7c\x26\x13\x06\x25\x21\x8d\xf7\xcd\x0f\x5b\xac\xc8\x4f\x35\xdb\xad" +
    "\x13\xc9\xfb\xf7\x0f\x0a\x20\xcd\x7c\xb7\xc0\xd1\x8c\xb6\x8d\x0f\x81\x88\xce\xc2" +
    "\xf1\xcb\xe3\xc1\x02\x3d\x09\x7e\x4d\xb8\x3f\x0e\x8b\x28\x78\x90\x77\x68\x81\xe3" +
    "\xc4\x88\x7a\x84\xe8\x06\x82\x9d\xb9\x35\xba\xc1\x20\x8c\x7a\x93\xfe\xd1\x16\xe5" +
    "\xc5\x34\x7e\x49\xc5\x9b\x80\x5a\x52\x37\xce\x56\x4f\x9d\x47\x38\xe9\x72\xb2\x37" +
    "\x01\x0f\xdf\x90\x8f\x14\xca\xce\x94\x10\xd9\x0e\x86\x08\xe9\xa3\x3d\x16\x6a\x8a" +
    "\x51\x00\x6a\x30\x7a\x3d\x4e\x65\x6e\x82\xa1\xe6\x59\xd4\xbb\x95\x5c\xbc\xc8\x36" +
    "\xe1\x95\xca\x7e\x41\x3c\x66\xc4\xdc\x41"
  end

=begin
#<OpenSSL::ASN1::ASN1Data:0x007fe55b8989e0
 @infinite_length=false,
 @tag=1,
 @tag_class=:APPLICATION,
 @value=
  [#<OpenSSL::ASN1::Sequence:0x007fe55b898a58
    @infinite_length=false,
    @tag=16,
    @tag_class=:UNIVERSAL,
    @tagging=nil,
    @value=
     [#<OpenSSL::ASN1::ASN1Data:0x007fe55b899e30
       @infinite_length=false,
       @tag=0,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007fe55b899fe8
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007fe55b89a088>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fe55b899c78
       @infinite_length=false,
       @tag=1,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralString:0x007fe55b899ca0
          @infinite_length=false,
          @tag=27,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value="DEMO.LOCAL">]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fe55b899250
       @infinite_length=false,
       @tag=2,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007fe55b8992a0
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007fe55b8998b8
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007fe55b8998e0
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007fe55b899930>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007fe55b8992f0
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007fe55b899408
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::GeneralString:0x007fe55b8996d8
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="krbtgt">,
                  #<OpenSSL::ASN1::GeneralString:0x007fe55b899458
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="DEMO.LOCAL">]>]>]>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007fe55b898af8
       @infinite_length=false,
       @tag=3,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007fe55b898b48
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007fe55b899048
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007fe55b899098
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007fe55b8990c0>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007fe55b898df0
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007fe55b898e90
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007fe55b898f80>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007fe55b898c88
             @infinite_length=false,
             @tag=2,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::OctetString:0x007fe55b898cb0
                @infinite_length=false,
                @tag=4,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 "\x81O\x84\xF4!\x93\xE5J\xCC%\x89S\xB3\xEEG\xF13\xDD\x15\xDCf\x05\x90\xE7g\x90\x1D\xBE\x03\xAAF\x02\xD0&M\e\xBB\x1F\t\xD4\xDCE\xBB\xA0|\xD0\xF2C\x9F\xAByL\x8F6\x9E\fXa\xC7\xAD`\xB2D1\xFE\x89@%\xFB\x8Bqi\"\x87\xABnQ\x8E:\xEDd\x16:\x7FM\xB6\xA1\xC8i\xD0\x12_\x01\xD8!8)\xE2\x97cZM\xBF\xC9\xD7\xE9\xC4\a(\x89\xDD\xC1a\xBA\xCC\x12r(\ep=\x1F\xAEP\xD5\x88[\xCA\x00U\xD8\xE9\xDD\x1C\x91~e\x99M\x97l\xB8\xC5\x89\xE1\xAFL\xE4\xB6:y\\\xCE\xF4\xA93y_i\xB9\x16\xBA\x12\x03)\xB1\x80\x89!\x1A\x93\xCD\xE7:\xBA\xCAW\x94G:i\x1A\x1A\x9D\x1D*\x1D6\x82\xFE">]>]>]>]>]>
=end
  let(:ticket_der) do
    "\x61\x82\x01\x0c\x30\x82\x01\x08\xa0\x03\x02\x01\x05\xa1\x0c\x1b" +
    "\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa2\x1f\x30\x1d\xa0" +
    "\x03\x02\x01\x01\xa1\x16\x30\x14\x1b\x06\x6b\x72\x62\x74\x67\x74" +
    "\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa3\x81\xd1\x30" +
    "\x81\xce\xa0\x03\x02\x01\x17\xa1\x03\x02\x01\x02\xa2\x81\xc1\x04" +
    "\x81\xbe\x81\x4f\x84\xf4\x21\x93\xe5\x4a\xcc\x25\x89\x53\xb3\xee" +
    "\x47\xf1\x33\xdd\x15\xdc\x66\x05\x90\xe7\x67\x90\x1d\xbe\x03\xaa" +
    "\x46\x02\xd0\x26\x4d\x1b\xbb\x1f\x09\xd4\xdc\x45\xbb\xa0\x7c\xd0" +
    "\xf2\x43\x9f\xab\x79\x4c\x8f\x36\x9e\x0c\x58\x61\xc7\xad\x60\xb2" +
    "\x44\x31\xfe\x89\x40\x25\xfb\x8b\x71\x69\x22\x87\xab\x6e\x51\x8e" +
    "\x3a\xed\x64\x16\x3a\x7f\x4d\xb6\xa1\xc8\x69\xd0\x12\x5f\x01\xd8" +
    "\x21\x38\x29\xe2\x97\x63\x5a\x4d\xbf\xc9\xd7\xe9\xc4\x07\x28\x89" +
    "\xdd\xc1\x61\xba\xcc\x12\x72\x28\x1b\x70\x3d\x1f\xae\x50\xd5\x88" +
    "\x5b\xca\x00\x55\xd8\xe9\xdd\x1c\x91\x7e\x65\x99\x4d\x97\x6c\xb8" +
    "\xc5\x89\xe1\xaf\x4c\xe4\xb6\x3a\x79\x5c\xce\xf4\xa9\x33\x79\x5f" +
    "\x69\xb9\x16\xba\x12\x03\x29\xb1\x80\x89\x21\x1a\x93\xcd\xe7\x3a" +
    "\xba\xca\x57\x94\x47\x3a\x69\x1a\x1a\x9d\x1d\x2a\x1d\x36\x82\xfe"
  end

  let(:cipher) do
    "\x2b\xea\x95\x7c\x26\x13\x06\x25\x21\x8d\xf7\xcd\x0f\x5b\xac\xc8" +
    "\x4f\x35\xdb\xad\x13\xc9\xfb\xf7\x0f\x0a\x20\xcd\x7c\xb7\xc0\xd1" +
    "\x8c\xb6\x8d\x0f\x81\x88\xce\xc2\xf1\xcb\xe3\xc1\x02\x3d\x09\x7e" +
    "\x4d\xb8\x3f\x0e\x8b\x28\x78\x90\x77\x68\x81\xe3\xc4\x88\x7a\x84" +
    "\xe8\x06\x82\x9d\xb9\x35\xba\xc1\x20\x8c\x7a\x93\xfe\xd1\x16\xe5" +
    "\xc5\x34\x7e\x49\xc5\x9b\x80\x5a\x52\x37\xce\x56\x4f\x9d\x47\x38" +
    "\xe9\x72\xb2\x37\x01\x0f\xdf\x90\x8f\x14\xca\xce\x94\x10\xd9\x0e" +
    "\x86\x08\xe9\xa3\x3d\x16\x6a\x8a\x51\x00\x6a\x30\x7a\x3d\x4e\x65" +
    "\x6e\x82\xa1\xe6\x59\xd4\xbb\x95\x5c\xbc\xc8\x36\xe1\x95\xca\x7e" +
    "\x41\x3c\x66\xc4\xdc\x41"
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::Model::ApReq correctly" do

      ticket = Rex::Proto::Kerberos::Model::Ticket.decode(ticket_der)

      authenticator = Rex::Proto::Kerberos::Model::EncryptedData.new(
        etype: Rex::Proto::Kerberos::Crypto::RC4_HMAC,
        cipher: cipher
      )

      ap_req.pvno = 5
      ap_req.msg_type = 14
      ap_req.options = 0
      ap_req.ticket = ticket
      ap_req.authenticator = authenticator

      expect(ap_req.encode).to eq(sample)
    end
  end
end
