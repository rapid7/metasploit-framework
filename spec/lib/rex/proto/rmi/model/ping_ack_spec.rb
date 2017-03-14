# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/proto/rmi'

RSpec.describe Rex::Proto::Rmi::Model::PingAck do

  subject(:ping_ack) do
    described_class.new
  end

  let(:sample) do
    "\x53"
  end

  let(:sample_io) { StringIO.new(sample) }

  describe "#decode" do
    it "returns the Rex::Proto::Rmi::Model::PingAck decoded" do
      expect(ping_ack.decode(sample_io)).to eq(ping_ack)
    end

    it "decodes stream_id correctly" do
      ping_ack.decode(sample_io)
      expect(ping_ack.stream_id).to eq(Rex::Proto::Rmi::Model::PING_ACK)
    end
  end

  describe "#encode" do
    it "encodes the PingAck correctly" do
      ping_ack.stream_id = Rex::Proto::Rmi::Model::PING_ACK
      expect(ping_ack.encode).to eq(sample)
    end
  end
end

