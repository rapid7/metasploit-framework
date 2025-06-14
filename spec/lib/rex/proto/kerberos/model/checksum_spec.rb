# -*- coding:binary -*-
require 'spec_helper'


RSpec.describe Rex::Proto::Kerberos::Model::Checksum do

  subject(:checksum) do
    described_class.new
  end

  let(:sample) do
    "\x30\x19\xa0\x03\x02\x01\x07\xa1\x12\x04\x10\x9e\xf0\x84\xd6\x81" +
    "\xe5\x16\x02\x32\xb1\xc3\x4e\xad\x83\x1d\x43"
  end

  let(:rsa_md5) { Rex::Proto::Kerberos::Crypto::Checksum::RSA_MD5 }

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::Model::Checksum correctly" do
      checksum.type = rsa_md5
      checksum.checksum = "\x9e\xf0\x84\xd6\x81\xe5\x16\x02\x32\xb1\xc3\x4e\xad\x83\x1d\x43"
      expect(checksum.encode).to eq(sample)
    end
  end

  describe "#decode" do
    it "decodes Rex::Proto::Kerberos::Model::Checksum correctly" do
      encoded_checksum = "\x30\x1a\xa0\x04\x02\x02\xff\x76\xa1\x12\x04\x10\xea\x62\x48\xe2\x8c\xe0\x76\x47\x06\xc7\x39\x99\x06\x35\x96\x89"
      expected_type = Rex::Proto::Kerberos::Crypto::Checksum::HMAC_MD5
      expected_checksum = "\xea\x62\x48\xe2\x8c\xe0\x76\x47\x06\xc7\x39\x99\x06\x35\x96\x89"
      checksum.decode(encoded_checksum)
      expect(checksum.type).to eq(expected_type)
      expect(checksum.checksum).to eq(expected_checksum)
    end
  end
end
