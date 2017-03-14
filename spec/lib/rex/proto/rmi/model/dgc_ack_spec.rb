# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/proto/rmi'

RSpec.describe Rex::Proto::Rmi::Model::DgcAck do

  subject(:dgc_ack) do
    described_class.new
  end

  let(:sample) do
    "\x54\xd2\x4f\xdf\x47\x00\x00\x01\x49\xb5\xe4\x92\x78\x80\x17"
  end

  let(:sample_io) { StringIO.new(sample) }

  describe "#decode" do
    it "returns the Rex::Proto::Rmi::Model::DgcAck decoded" do
      expect(dgc_ack.decode(sample_io)).to eq(dgc_ack)
    end

    it "decodes stream_id correctly" do
      dgc_ack.decode(sample_io)
      expect(dgc_ack.stream_id).to eq(Rex::Proto::Rmi::Model::DGC_ACK_MESSAGE)
    end

    it "decodes address correctly" do
      dgc_ack.decode(sample_io)
      expect(dgc_ack.unique_identifier).to eq("\xd2\x4f\xdf\x47\x00\x00\x01\x49\xb5\xe4\x92\x78\x80\x17")
    end
  end

  describe "#encode" do
    it "encodes the DbgAck correctly" do
      dgc_ack.stream_id = Rex::Proto::Rmi::Model::DGC_ACK_MESSAGE
      dgc_ack.unique_identifier = "\xd2\x4f\xdf\x47\x00\x00\x01\x49\xb5\xe4\x92\x78\x80\x17"

      expect(dgc_ack.encode).to eq(sample)
    end
  end
end
