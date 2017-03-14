# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/proto/rmi'

RSpec.describe Rex::Proto::Rmi::Model::Ping do

  subject(:ping) do
    described_class.new
  end

  let(:sample) do
    "\x52"
  end

  let(:sample_io) { StringIO.new(sample) }

  describe "#decode" do
    it "returns the Rex::Proto::Rmi::Model::Ping decoded" do
      expect(ping.decode(sample_io)).to eq(ping)
    end

    it "decodes stream_id correctly" do
      ping.decode(sample_io)
      expect(ping.stream_id).to eq(Rex::Proto::Rmi::Model::PING_MESSAGE)
    end
  end

  describe "#encode" do
    it "encodes the Ping correctly" do
      ping.stream_id = Rex::Proto::Rmi::Model::PING_MESSAGE
      expect(ping.encode).to eq(sample)
    end
  end
end
