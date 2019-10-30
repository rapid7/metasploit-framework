# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::CredentialCache::Time do

  subject(:time) do
    described_class.new
  end

  let(:sample) do
    "\x00\x00\x00\x00\x00\x00\x00\x01" +
    "\x00\x00\x00\x02\x00\x00\x00\x03"
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::CredentialCache::Principal correctly" do
      time.auth_time = 0
      time.start_time = 1
      time.end_time = 2
      time.renew_till = 3

      expect(time.encode).to eq(sample)
    end
  end
end