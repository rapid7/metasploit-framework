# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::Ticket do

  subject(:ticket) do
    described_class.new
  end

=begin
#<OpenSSL::ASN1::ASN1Data:0x007f93b206ed78
 @infinite_length=false,
 @tag=1,
 @tag_class=:APPLICATION,
 @value=
  [#<OpenSSL::ASN1::Sequence:0x007f93b206eda0
    @infinite_length=false,
    @tag=16,
    @tag_class=:UNIVERSAL,
    @tagging=nil,
    @value=
     [#<OpenSSL::ASN1::ASN1Data:0x007f93b2094ca8
       @infinite_length=false,
       @tag=0,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007f93b2094cd0
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007f93b2094e10>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007f93b2094b90
       @infinite_length=false,
       @tag=1,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralString:0x007f93b2094bb8
          @infinite_length=false,
          @tag=27,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value="DEMO.LOCAL">]>,
      #<OpenSSL::ASN1::ASN1Data:0x007f93b2094078
       @infinite_length=false,
       @tag=2,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007f93b2094230
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007f93b2094870
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007f93b20948c0
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007f93b2094988>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007f93b2094280
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007f93b20943e8
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::GeneralString:0x007f93b20944d8
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="krbtgt">,
                  #<OpenSSL::ASN1::GeneralString:0x007f93b2094410
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="DEMO.LOCAL">]>]>]>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007f93b206f728
       @infinite_length=false,
       @tag=3,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007f93b206f8e0
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007f93b206fbd8
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007f93b206fc28
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007f93b206fc50>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007f93b206fae8
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007f93b206fb60
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007f93b206fb88>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007f93b206f9f8
             @infinite_length=false,
             @tag=2,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::OctetString:0x007f93b206fa20
                @infinite_length=false,
                @tag=4,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 "U\xE7E\xC3o\xA2(G\xAB\x9C\x86\x13\xEB\x1D\xA8\x98\xECg\x1C\x1F\x15Fk\xE0J\xF2M=\xF7\xE41zO\x15/`\xDD\x98\xA8\xE1\x97ko\xC1$Fl\xA9\x1E\xE26'\xE3\xFA\x99\f\x9Bw\f\xE2X\x02h\xC4T*,]lK\xC8\xBC\x04\x8F\nD'x\xDCK>\x01\xBE\xAC\xF7\x8EzP\xC6>w\xD9e$\xD5\x1A\x18\xA1\x84q\x85\x98/T\x8BV\xE3\xFB,\xE20\x84\x06UU\xEA1\x8B\x84\x00\xE3\x1A\xC3\xA8\xC2\xAC\xC0x?Ght\xCCb\xA6\xCF\xF4k\xAE\xAF'\xDE\x1AM\xB7\xA8\x9Fvzy*B\x12{\xD2\xBE\xC9\x98|D8@\xBDI\xCD>\xDCe\xC7\x8BD\xF5\xA5\xD4f\x0E\xFDX\x9D19'\xD7\xFC\x81\a\xA3*\x1C<">]>]>]>]>]>
=end
  let(:as_ticket) do
    "\x61\x82\x01\x0c" +
    "\x30\x82\x01\x08\xa0\x03\x02\x01\x05\xa1\x0c\x1b\x0a\x44\x45\x4d" +
    "\x4f\x2e\x4c\x4f\x43\x41\x4c\xa2\x1f\x30\x1d\xa0\x03\x02\x01\x01" +
    "\xa1\x16\x30\x14\x1b\x06\x6b\x72\x62\x74\x67\x74\x1b\x0a\x44\x45" +
    "\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xa3\x81\xd1\x30\x81\xce\xa0\x03" +
    "\x02\x01\x17\xa1\x03\x02\x01\x02\xa2\x81\xc1\x04\x81\xbe\x55\xe7" +
    "\x45\xc3\x6f\xa2\x28\x47\xab\x9c\x86\x13\xeb\x1d\xa8\x98\xec\x67" +
    "\x1c\x1f\x15\x46\x6b\xe0\x4a\xf2\x4d\x3d\xf7\xe4\x31\x7a\x4f\x15" +
    "\x2f\x60\xdd\x98\xa8\xe1\x97\x6b\x6f\xc1\x24\x46\x6c\xa9\x1e\xe2" +
    "\x36\x27\xe3\xfa\x99\x0c\x9b\x77\x0c\xe2\x58\x02\x68\xc4\x54\x2a" +
    "\x2c\x5d\x6c\x4b\xc8\xbc\x04\x8f\x0a\x44\x27\x78\xdc\x4b\x3e\x01" +
    "\xbe\xac\xf7\x8e\x7a\x50\xc6\x3e\x77\xd9\x65\x24\xd5\x1a\x18\xa1" +
    "\x84\x71\x85\x98\x2f\x54\x8b\x56\xe3\xfb\x2c\xe2\x30\x84\x06\x55" +
    "\x55\xea\x31\x8b\x84\x00\xe3\x1a\xc3\xa8\xc2\xac\xc0\x78\x3f\x47" +
    "\x68\x74\xcc\x62\xa6\xcf\xf4\x6b\xae\xaf\x27\xde\x1a\x4d\xb7\xa8" +
    "\x9f\x76\x7a\x79\x2a\x42\x12\x7b\xd2\xbe\xc9\x98\x7c\x44\x38\x40" +
    "\xbd\x49\xcd\x3e\xdc\x65\xc7\x8b\x44\xf5\xa5\xd4\x66\x0e\xfd\x58" +
    "\x9d\x31\x39\x27\xd7\xfc\x81\x07\xa3\x2a\x1c\x3c"
  end

  describe "#decode" do
    context "when decoding AS Response ticket" do
      it "returns the Rex::Proto::Kerberos::Model::Ticket decoded" do
        expect(ticket.decode(as_ticket)).to eq(ticket)
      end

      it "decodes tkt_vno correctly" do
        ticket.decode(as_ticket)
        expect(ticket.tkt_vno).to eq(5)
      end

      it "decodes realm correctly" do
        ticket.decode(as_ticket)
        expect(ticket.realm).to eq('DEMO.LOCAL')
      end

      it "decodes sname correctly" do
        ticket.decode(as_ticket)
        expect(ticket.sname.name_string).to eq(['krbtgt', 'DEMO.LOCAL'])
      end

      it "retrieves the encrypted part" do
        ticket.decode(as_ticket)
        expect(ticket.enc_part.cipher.length).to eq(190)
      end
    end
  end

  describe "#encode" do
    context "when encoding TGS Request ticket" do
      it "re-encodes the AS-RESP ticket correctly" do
        ticket.decode(as_ticket)
        expect(ticket.encode).to eq(as_ticket)
      end
    end
  end

end
