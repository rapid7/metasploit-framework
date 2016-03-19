# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/kademlia/bootstrap_request'

RSpec.describe Rex::Proto::Kademlia::BootstrapRequest do
  subject(:bootstrap) do
    described_class.new
  end

  describe '#initialize' do
    it 'constructs properly' do
      expect(bootstrap.type).to eq(Rex::Proto::Kademlia::BOOTSTRAP_REQUEST)
      expect(bootstrap.body).to eq('')
    end
  end

  describe '#to_str' do
    it 'packs properly' do
      expect(bootstrap.to_str).to eq("\xE4\x01")
    end
  end
end
