# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos'

RSpec.describe Rex::Proto::Kerberos::Pac::ClientInfo do

  subject(:client_info) do
    described_class.new
  end

  let(:sample) do
    "\x80\x60\x06\x1b\xbe\x18\xd0\x01\x08\x00\x6a\x00\x75\x00\x61\x00\x6e\x00"
  end

  describe "#encode" do
    context "when RSA-MD5 checksum" do
      it "encodes the ServerChecksums correctly" do
        client_info.client_id = Time.new(2014, 12, 15, 23, 23, 17, '+00:00')
        client_info.name = 'juan'
        expect(client_info.encode).to eq(sample)
      end
    end
  end
end
