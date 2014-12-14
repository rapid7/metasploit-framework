# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

describe Rex::Proto::Kerberos::Model::Message::KrbError do

  subject(:krb_error) do
    described_class.new
  end

  let(:msg_type) { 30 }
  let(:error_code_generic) { 60 }

=begin
#<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbc370
 @infinite_length=false,
 @tag=30,
 @tag_class=:APPLICATION,
 @value=
  [#<OpenSSL::ASN1::Sequence:0x007ff1f7cbc4b0
    @infinite_length=false,
    @tag=16,
    @tag_class=:UNIVERSAL,
    @tagging=nil,
    @value=
     [#<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbd770
       @infinite_length=false,
       @tag=0,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff1f7cbd810
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff1f7cbd838>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbd568
       @infinite_length=false,
       @tag=1,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff1f7cbd5e0
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff1f7cbd6a8>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbd338
       @infinite_length=false,
       @tag=4,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralizedTime:0x007ff1f7cbd360
          @infinite_length=false,
          @tag=24,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=2014-12-14 06:54:01 UTC>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbd0b8
       @infinite_length=false,
       @tag=5,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff1f7cbd1a8
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff1f7cbd248>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbcd70
       @infinite_length=false,
       @tag=6,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Integer:0x007ff1f7cbce10
          @infinite_length=false,
          @tag=2,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=#<OpenSSL::BN:0x007ff1f7cbd018>>]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbcb18
       @infinite_length=false,
       @tag=9,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::GeneralString:0x007ff1f7cbcb40
          @infinite_length=false,
          @tag=27,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value="DEMO.LOCAL">]>,
      #<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbc4d8
       @infinite_length=false,
       @tag=10,
       @tag_class=:CONTEXT_SPECIFIC,
       @value=
        [#<OpenSSL::ASN1::Sequence:0x007ff1f7cbc550
          @infinite_length=false,
          @tag=16,
          @tag_class=:UNIVERSAL,
          @tagging=nil,
          @value=
           [#<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbc910
             @infinite_length=false,
             @tag=0,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Integer:0x007ff1f7cbc960
                @infinite_length=false,
                @tag=2,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=#<OpenSSL::BN:0x007ff1f7cbc988>>]>,
            #<OpenSSL::ASN1::ASN1Data:0x007ff1f7cbc578
             @infinite_length=false,
             @tag=1,
             @tag_class=:CONTEXT_SPECIFIC,
             @value=
              [#<OpenSSL::ASN1::Sequence:0x007ff1f7cbc5f0
                @infinite_length=false,
                @tag=16,
                @tag_class=:UNIVERSAL,
                @tagging=nil,
                @value=
                 [#<OpenSSL::ASN1::GeneralString:0x007ff1f7cbc730
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="krbtgt">,
                  #<OpenSSL::ASN1::GeneralString:0x007ff1f7cbc618
                   @infinite_length=false,
                   @tag=27,
                   @tag_class=:UNIVERSAL,
                   @tagging=nil,
                   @value="DEMO.LOCAL">]>]>]>]>]>]>
=end

  let(:generic_error) do
    "\x7e\x5a\x30\x58\xa0\x03\x02\x01\x05\xa1\x03\x02" +
    "\x01\x1e\xa4\x11\x18\x0f\x32\x30\x31\x34\x31\x32\x31\x34\x30\x36" +
    "\x35\x34\x30\x31\x5a\xa5\x05\x02\x03\x0b\x0d\x5b\xa6\x03\x02\x01" +
    "\x3c\xa9\x0c\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c\xaa" +
    "\x1f\x30\x1d\xa0\x03\x02\x01\x02\xa1\x16\x30\x14\x1b\x06\x6b\x72" +
    "\x62\x74\x67\x74\x1b\x0a\x44\x45\x4d\x4f\x2e\x4c\x4f\x43\x41\x4c"
  end

  describe "#decode" do
    context "generic error" do
      it "returns the Rex::Proto::Kerberos::Model::Message::KrbError decoded" do
        expect(krb_error.decode(generic_error)).to eq(krb_error)
      end

      it "decodes msg_type correctly" do
        krb_error.decode(generic_error)
        expect(krb_error.msg_type).to eq(msg_type)
      end

      it "decodes stime correctly" do
        krb_error.decode(generic_error)
        expect(krb_error.stime.to_s).to eq('2014-12-14 06:54:01 UTC')
      end

      it "decodes susec correctly" do
        krb_error.decode(generic_error)
        expect(krb_error.susec).to eq(724315)
      end

      it "decodes error_code correctly" do
        krb_error.decode(generic_error)
        expect(krb_error.error_code).to eq(error_code_generic)
      end

      it "decodes realm correctly" do
        krb_error.decode(generic_error)
        expect(krb_error.realm).to eq('DEMO.LOCAL')
      end

      it "decodes sname correctly" do
        krb_error.decode(generic_error)
        expect(krb_error.sname.name_string).to eq(['krbtgt', 'DEMO.LOCAL'])
      end
    end
  end
end
