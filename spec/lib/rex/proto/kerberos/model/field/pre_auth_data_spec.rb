# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

describe Rex::Proto::Kerberos::Model::Field::PreAuthData do

  subject(:pre_auth_data) do
    described_class.new
  end

  let(:timestamp_sample) do
    "\x30\x48\xa1\x03\x02\x01\x02\xa2\x41\x04\x3f\x30\x3d\xa0\x03\x02" +
    "\x01\x17\xa2\x36\x04\x34\x60\xae\x53\xa5\x0b\x56\x2e\x46\x61\xd9" +
    "\xd6\x89\x98\xfc\x79\x9d\x45\x73\x7d\x0d\x8a\x78\x84\x4d\xd7\x7c" +
    "\xc6\x50\x08\x8d\xab\x22\x79\xc3\x8d\xd3\xaf\x9f\x5e\xb7\xb8\x9b" +
    "\x57\xc5\xc9\xc5\xea\x90\x89\xc3\x63\x58"
  end

  let(:pac_sample) do
    "\x30\x11\xa1\x04\x02\x02" +
    "\x00\x80\xa2\x09\x04\x07\x30\x05\xa0\x03\x01\x01\x00"
  end

  describe ".new" do
    it "returns a Rex::Proto::Kerberos::Model::Field::PreAuthData" do
      expect(pre_auth_data).to be_a(Rex::Proto::Kerberos::Model::Field::PreAuthData)
    end
  end

  describe "#decode" do
    context "when PAC-ENC-TIMESTAMP" do
      it "returns the decoded Rex::Proto::Kerberos::Model::Field::PreAuthData" do
        expect(pre_auth_data.decode(timestamp_sample)).to eq(pre_auth_data)
      end

      it "decodes type" do
        pre_auth_data.decode(timestamp_sample)
        expect(pre_auth_data.type).to eq(2)
      end

      it "decodes value" do
        pre_auth_data.decode(timestamp_sample)
        expect(pre_auth_data.value.length).to eq(63)
      end
    end

    context "when PA-PAC-REQUEST" do
      it "returns the decoded Rex::Proto::Kerberos::Model::Field::PreAuthData" do
        expect(pre_auth_data.decode(pac_sample)).to eq(pre_auth_data)
      end

      it "decodes type" do
        pre_auth_data.decode(pac_sample)
        expect(pre_auth_data.type).to eq(128)
      end

      it "decodes value" do
        pre_auth_data.decode(pac_sample)
        expect(pre_auth_data.value.length).to eq(7)
      end
    end
  end

end
