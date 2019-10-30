# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Model::Checksum do

  subject(:checksum) do
    described_class.new
  end

  let(:sample) do
    "\x30\x19\xa0\x03\x02\x01\x07\xa1\x12\x04\x10\x9e\xf0\x84\xd6\x81" +
    "\xe5\x16\x02\x32\xb1\xc3\x4e\xad\x83\x1d\x43"
  end

  let(:rsa_md5) { Rex::Proto::Kerberos::Crypto::RSA_MD5 }

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::Model::Checksum correctly" do
      checksum.type = rsa_md5
      checksum.checksum = "\x9e\xf0\x84\xd6\x81\xe5\x16\x02\x32\xb1\xc3\x4e\xad\x83\x1d\x43"
      expect(checksum.encode).to eq(sample)
    end
  end
end
