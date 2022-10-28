# -*- coding:binary -*-
require 'spec_helper'

require 'rex/proto/kerberos/pac/krb5_pac'

RSpec.describe Rex::Proto::Kerberos::Pac::Krb5ClientInfo do

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
        expect(client_info.to_binary_s).to eq(sample)
      end
    end
  end

  describe "#read" do
    it "does not break" do
      BinData.trace_reading do
        x = Rex::Proto::Kerberos::Pac::Krb5ClientInfo.read(sample)
        pp x.snapshot
        expect(x).to be_a(Rex::Proto::Kerberos::Pac::Krb5ClientInfo)
      end
    end
    it "encodes the ServerChecksums correctly" do
      client_info.client_id = Time.new(2014, 12, 15, 23, 23, 17, '+00:00')
      client_info.name = 'juan'
      expect(client_info).to eq(Rex::Proto::Kerberos::Pac::Krb5ClientInfo.read(sample))
    end
  end
end
