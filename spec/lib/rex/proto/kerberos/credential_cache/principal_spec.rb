# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::CredentialCache::Principal do

  subject(:principal) do
    described_class.new
  end

  let(:sample) do
    "\x00\x00\x00\x01\x00\x00\x00\x01" +
    "\x00\x00\x00\x0a\x44\x45\x4d\x4f" +
    "\x2e\x4c\x4f\x43\x41\x4c\x00\x00" +
    "\x00\x04\x6a\x75\x61\x6e"
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::CredentialCache::Principal correctly" do
      principal.name_type = 1
      principal.realm = 'DEMO.LOCAL'
      principal.components = ['juan']

      expect(principal.encode).to eq(sample)
    end
  end
end