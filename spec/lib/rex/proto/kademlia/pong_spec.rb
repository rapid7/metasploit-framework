# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/kademlia/pong'

RSpec.describe Rex::Proto::Kademlia::Pong do
  let(:port) { 12345 }
  subject(:pong) do
    described_class.new(port)
  end

  describe '#initialize' do
    it 'constructs properly' do
      expect(pong.type).to eq(Rex::Proto::Kademlia::PONG)
      expect(pong.port).to eq(port)
    end
  end

  describe '#to_str' do
    it 'packs properly' do
      expect(pong.to_str).to eq("\xE4\x61\x39\x30")
    end
  end

  describe '#from_data' do
    it 'unpacks supported valid pongs properly' do
      unpacked = described_class.from_data("\xE4\x61\x9E\x86")
      expect(unpacked.type).to eq(Rex::Proto::Kademlia::PONG)
      expect(unpacked.port).to eq(34462)
    end

    it 'does not decode overly small pongs' do
      expect(described_class.from_data("\xE4\x61\x01")).to eq(nil)
    end

    it 'does not decode overly large pongs' do
      expect(described_class.from_data("\xE4\x61\x01\x02\x03")).to eq(nil)
    end
  end
end
