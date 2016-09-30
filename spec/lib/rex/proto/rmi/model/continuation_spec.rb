# -*- coding:binary -*-
require 'spec_helper'

require 'stringio'
require 'rex/proto/rmi'

RSpec.describe Rex::Proto::Rmi::Model::Continuation do

  subject(:continuation) do
    described_class.new
  end

  let(:sample) do
    "\x00\x0e\x31\x37\x32\x2e\x31\x36\x2e\x31\x35\x38\x2e\x31\x33\x32" +
    "\x00\x00\x00\x00"
  end

  let(:sample_io) { StringIO.new(sample) }

  describe "#decode" do
    it "returns the Rex::Proto::Rmi::Model::Continuation decoded" do
      expect(continuation.decode(sample_io)).to eq(continuation)
    end

    it "decodes length correctly" do
      continuation.decode(sample_io)
      expect(continuation.length).to eq(14)
    end

    it "decodes address correctly" do
      continuation.decode(sample_io)
      expect(continuation.address).to eq('172.16.158.132')
    end

    it "decodes port correctly" do
      continuation.decode(sample_io)
      expect(continuation.port).to eq(0)
    end
  end

  describe "#encode" do
    it "encodes the Continuation correctly" do
      continuation.address = '172.16.158.132'
      continuation.length = continuation.address.length
      continuation.port = 0

      expect(continuation.encode).to eq(sample)
    end
  end
end
