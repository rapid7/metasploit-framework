# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/proto/rmi'

RSpec.describe Rex::Proto::Rmi::Model::OutputHeader do

  subject(:output_header) do
    described_class.new
  end

  let(:stream_protocol) do
    "\x4a\x52\x4d\x49\x00\x02\x4b"
  end

  let(:stream_protocol_io) { StringIO.new(stream_protocol) }

  describe "#decode" do
    context "when Stream Protocol" do
      it "returns the Rex::Proto::Rmi::Model::OutputHeader decoded" do
        expect(output_header.decode(stream_protocol_io)).to eq(output_header)
      end

      it "decodes signature correctly" do
        output_header.decode(stream_protocol_io)
        expect(output_header.signature).to eq(Rex::Proto::Rmi::Model::SIGNATURE)
      end

      it "decodes version correctly" do
        output_header.decode(stream_protocol_io)
        expect(output_header.version).to eq(2)
      end

      it "decodes protocol correctly" do
        output_header.decode(stream_protocol_io)
        expect(output_header.protocol).to eq(Rex::Proto::Rmi::Model::STREAM_PROTOCOL)
      end
    end
  end

  describe "#encode" do
    context "when Stream Protocol" do
      it "encodes the OutputHeader correctly" do
        output_header.signature = Rex::Proto::Rmi::Model::SIGNATURE
        output_header.version = 2
        output_header.protocol = Rex::Proto::Rmi::Model::STREAM_PROTOCOL

        expect(output_header.encode).to eq(stream_protocol)
      end
    end

    context "when version field missed" do
      it "doesn't encodes the version" do
        output_header.signature = Rex::Proto::Rmi::Model::SIGNATURE
        output_header.protocol = Rex::Proto::Rmi::Model::STREAM_PROTOCOL

        expect(output_header.encode).to eq("\x4a\x52\x4d\x49\x4b")
      end
    end
  end
end
