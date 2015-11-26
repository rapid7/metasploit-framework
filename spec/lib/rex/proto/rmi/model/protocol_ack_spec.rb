# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/proto/rmi'

RSpec.describe Rex::Proto::Rmi::Model::ProtocolAck do

  subject(:protocol_ack) do
    described_class.new
  end

  let(:sample) do
    "\x4e\x00\x0e\x31\x37\x32\x2e\x31\x36\x2e\x31\x35\x38\x2e\x31\x33" +
    "\x32\x00\x00\x06\xea"
  end

  let(:sample_io) { StringIO.new(sample) }

  describe "#decode" do
    it "returns the Rex::Proto::Rmi::Model::ProtocolAck decoded" do
      expect(protocol_ack.decode(sample_io)).to eq(protocol_ack)
    end

    it "decodes stream_id correctly" do
      protocol_ack.decode(sample_io)
      expect(protocol_ack.stream_id).to eq(Rex::Proto::Rmi::Model::PROTOCOL_ACK)
    end

    it "decodes length correctly" do
      protocol_ack.decode(sample_io)
      expect(protocol_ack.length).to eq(14)
    end

    it "decodes address correctly" do
      protocol_ack.decode(sample_io)
      expect(protocol_ack.address).to eq('172.16.158.132')
    end

    it "decodes port correctly" do
      protocol_ack.decode(sample_io)
      expect(protocol_ack.port).to eq(1770)
    end
  end

  describe "#encode" do
    it "encodes the OutputHeader correctly" do
      protocol_ack.stream_id = Rex::Proto::Rmi::Model::PROTOCOL_ACK
      protocol_ack.address = '172.16.158.132'
      protocol_ack.length = protocol_ack.address.length
      protocol_ack.port = 1770

      expect(protocol_ack.encode).to eq(sample)
    end
  end
end
