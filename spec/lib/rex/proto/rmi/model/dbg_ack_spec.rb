# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/proto/rmi'

describe Rex::Proto::Rmi::Model::DbgAck do

  subject(:dbg_ack) do
    described_class.new
  end

  let(:sample) do
    "\x54\xd2\x4f\xdf\x47\x00\x00\x01\x49\xb5\xe4\x92\x78\x80\x17"
  end

  let(:sample_io) { StringIO.new(sample) }

  describe "#decode" do
    it "returns the Rex::Proto::Rmi::Model::DbgAck decoded" do
      expect(dbg_ack.decode(sample_io)).to eq(dbg_ack)
    end

    it "decodes stream_id correctly" do
      dbg_ack.decode(sample_io)
      expect(dbg_ack.stream_id).to eq(Rex::Proto::Rmi::Model::DBG_ACK_MESSAGE)
    end

    it "decodes address correctly" do
      dbg_ack.decode(sample_io)
      expect(dbg_ack.unique_identifier).to eq("\xd2\x4f\xdf\x47\x00\x00\x01\x49\xb5\xe4\x92\x78\x80\x17")
    end
  end

  describe "#encode" do
    it "encodes the DbgAck correctly" do
      dbg_ack.stream_id = Rex::Proto::Rmi::Model::DBG_ACK_MESSAGE
      dbg_ack.unique_identifier = "\xd2\x4f\xdf\x47\x00\x00\x01\x49\xb5\xe4\x92\x78\x80\x17"

      expect(dbg_ack.encode).to eq(sample)
    end
  end
end
