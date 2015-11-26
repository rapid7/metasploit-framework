# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::CredentialCache::KeyBlock do

  subject(:key_block) do
    described_class.new
  end

  let(:sample) do
    "\x00\x17\x00\x00\x00\x10\xf5\x39" +
    "\xcf\x42\x8a\x03\x2d\x97\x5b\x85" +
    "\x04\x6e\xe7\xce\x67\x55"
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::CredentialCache::KeyBlock correctly" do
      key_block.e_type = 0
      key_block.key_type = Rex::Proto::Kerberos::Crypto::RC4_HMAC
      key_block.key_value = "\xf5\x39\xcf\x42\x8a\x03\x2d\x97\x5b\x85\x04\x6e\xe7\xce\x67\x55"

      expect(key_block.encode).to eq(sample)
    end
  end
end