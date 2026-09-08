# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Simple::Statistics do
  let(:framework) { double('Framework') }
  let(:cache_instance) { Msf::Modules::Metadata::Cache.instance }
  let(:mock_counts) do
    {
      exploit: 2400,
      auxiliary: 1300,
      post: 400,
      payload: 900,
      encoder: 50,
      nop: 15,
      evasion: 10
    }
  end

  before do
    allow(cache_instance).to receive(:module_counts).and_return(nil)
    allow(cache_instance).to receive(:update_stats) do
      allow(cache_instance).to receive(:module_counts).and_return(mock_counts)
    end
  end

  describe '#initialize' do
    it 'does not call update_stats on the cache' do
      expect(cache_instance).not_to receive(:update_stats)
      described_class.new(framework)
    end
  end

  describe '#num_exploits' do
    it 'triggers update_stats on first access' do
      stats = described_class.new(framework)
      expect(cache_instance).to receive(:update_stats).once do
        allow(cache_instance).to receive(:module_counts).and_return(mock_counts)
      end
      stats.num_exploits
    end

    it 'does not re-trigger update_stats on subsequent calls' do
      stats = described_class.new(framework)
      stats.num_exploits
      expect(cache_instance).not_to receive(:update_stats)
      stats.num_exploits
    end

    it 'returns the correct count' do
      stats = described_class.new(framework)
      expect(stats.num_exploits).to eq(2400)
    end
  end

  describe 'all num_* methods return correct counts' do
    subject(:stats) { described_class.new(framework) }

    it { expect(stats.num_encoders).to eq(50) }
    it { expect(stats.num_exploits).to eq(2400) }
    it { expect(stats.num_nops).to eq(15) }
    it { expect(stats.num_payloads).to eq(900) }
    it { expect(stats.num_auxiliary).to eq(1300) }
    it { expect(stats.num_post).to eq(400) }
    it { expect(stats.num_evasion).to eq(10) }
  end
end
