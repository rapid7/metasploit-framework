# -*- coding:binary -*-
require 'spec_helper'

RSpec.describe Rex::Proto::Kerberos::Model::HostAddress do

  subject(:host_address) do
    described_class.new
  end

  let(:host_address_sample) do
    "\x30\x0d\xa0\x03\x02\x01\x02\xa1\x06\x04\x04\xc0\x00\x02\x02"
  end

  describe "#decode" do
    it "decodes type" do
      host_address.decode(host_address_sample)

      expect(host_address.type).to eq(Rex::Proto::Kerberos::Model::AddressType::IPV4)
    end

    it "decodes address" do
      host_address.decode(host_address_sample)

      expect(host_address.address).to eq(Rex::Socket.addr_aton("192.0.2.2"))
    end
  end

  describe "#encode" do
    it "encodes Rex::Proto::Kerberos::Model::PreAuthData correctly" do
      host_address.decode(host_address_sample)
      expect(host_address.encode).to eq(host_address_sample)
    end
  end
end
