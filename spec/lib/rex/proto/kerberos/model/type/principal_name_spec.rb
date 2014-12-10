# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

describe Rex::Proto::Kerberos::Model::Type::PrincipalName do

  subject(:principal_name) do
    described_class.new
  end

  let(:sample_single_name) do
    "\x30\x0f\xa0\x03\x02\x01\x01\xa1" +
    "\x08\x30\x06\x1b\x04\x6a\x75\x61" +
    "\x6e"
  end

  let(:sample_multiple_name) do
    "\x30\x1d\xa0\x03\x02\x01\x01\xa1" +
    "\x16\x30\x14\x1b\x06\x6b\x72\x62" +
    "\x74\x67\x74\x1b\x0a\x44\x45\x4d" +
    "\x4f\x2e\x4c\x4f\x43\x41\x4c"
  end

  describe ".new" do
    it "returns a Rex::Proto::Kerberos::Model::Type::PrincipalName" do
      expect(principal_name).to be_a(Rex::Proto::Kerberos::Model::Type::PrincipalName)
    end
  end

  describe "#decode" do
    context "when PrincipalName with single name" do
      it "returns the PrincipalName instance" do
        expect(principal_name.decode(sample_single_name)).to eq(principal_name)
      end

      it "decodes name_type" do
        principal_name.decode(sample_single_name)
        expect(principal_name.name_type).to eq(1)
      end

      it "decodes name_string" do
        principal_name.decode(sample_single_name)
        expect(principal_name.name_string).to eq(['juan'])
      end
    end

    context "when PrincipalName with several names" do
      it "returns the PrincipalName instance" do
        expect(principal_name.decode(sample_multiple_name)).to eq(principal_name)
      end

      it "decodes name_type" do
        principal_name.decode(sample_multiple_name)
        expect(principal_name.name_type).to eq(1)
      end

      it "decodes name_string" do
        principal_name.decode(sample_multiple_name)
        expect(principal_name.name_string).to eq(['krbtgt', 'DEMO.LOCAL'])
      end
    end
  end

  describe "#encode" do
    it "encodes correctly PrincipalName with single name" do
      principal_name.name_type = 1
      principal_name.name_string = ['juan']
      expect(principal_name.encode.unpack('C*')).to eq(sample_single_name.unpack('C*'))
    end


    it "encodes correctly PrincipalName with several names" do
      principal_name.name_type = 1
      principal_name.name_string = ['krbtgt', 'DEMO.LOCAL']
      expect(principal_name.encode.unpack('C*')).to eq(sample_multiple_name.unpack('C*'))
    end
  end
end
