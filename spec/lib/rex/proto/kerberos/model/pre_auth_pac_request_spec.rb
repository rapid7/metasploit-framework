# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::PreAuthPacRequest do

  subject(:pre_auth_pac_request) do
    described_class.new
  end

=begin
#<OpenSSL::ASN1::Sequence:0x007ff9c191b730
 @infinite_length=false,
 @tag=16,
 @tag_class=:UNIVERSAL,
 @tagging=nil,
 @value=
  [#<OpenSSL::ASN1::ASN1Data:0x007ff9c191b7f8
    @infinite_length=false,
    @tag=0,
    @tag_class=:CONTEXT_SPECIFIC,
    @value=
     [#<OpenSSL::ASN1::Boolean:0x007ff9c191b820
       @infinite_length=false,
       @tag=1,
       @tag_class=:UNIVERSAL,
       @tagging=nil,
       @value=false>]>]>
=end
  let(:pac_sample) do
    "\x30\x05\xa0\x03\x01\x01\x00"
  end

  describe "#decode" do
    it "returns the decoded Rex::Proto::Kerberos::Model::PreAuthData" do
      expect(pre_auth_pac_request.decode(pac_sample)).to eq(pre_auth_pac_request)
    end

    it "decodes value" do
      pre_auth_pac_request.decode(pac_sample)
      expect(pre_auth_pac_request.value).to be_falsey
    end
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::Model::PreAuthPacRequest correctly" do
      pre_auth_pac_request.decode(pac_sample)
      expect(pre_auth_pac_request.encode).to eq(pac_sample)
    end
  end
end
