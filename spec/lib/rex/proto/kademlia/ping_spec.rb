# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/kademlia/ping'

RSpec.describe Rex::Proto::Kademlia::Ping do
  subject(:ping) do
    described_class.new
  end

  describe '#initialize' do
    it 'constructs properly' do
      expect(ping.type).to eq(Rex::Proto::Kademlia::PING)
      expect(ping.body).to eq('')
    end
  end

  describe '#to_str' do
    it 'packs properly' do
      expect(ping.to_str).to eq("\xE4\x60")
    end
  end
end
