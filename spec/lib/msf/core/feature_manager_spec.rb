# -*- coding:binary -*-

require 'spec_helper'
require 'msf/core/feature_manager'

RSpec.describe Msf::FeatureManager do
  let(:mock_features) do
    [
      {
        name: 'filtered_options',
        description: 'Add option filtering functionality to Metasploit',
        enabled: false
      },
      {
        name: 'new_search_capabilities',
        description: 'Add new search capabilities to Metasploit',
        enabled: true
      }
    ]
  end
  let(:mock_framework) { instance_double(Msf::Framework) }
  let(:subject) { described_class.new(mock_framework) }

  before(:each) do
    stub_const('Msf::FeatureManager::DEFAULTS', mock_features)
  end

  describe '#all' do
    it { expect(subject.all).to eql mock_features }
  end

  describe '#enabled?' do
    it { expect(subject.enabled?('missing_option')).to be false }
    it { expect(subject.enabled?('filtered_options')).to be false }
    it { expect(subject.enabled?('new_search_capabilities')).to be true }
  end

  describe '#exists?' do
    it { expect(subject.exists?('missing_option')).to be false }
    it { expect(subject.exists?('filtered_options')).to be true }
    it { expect(subject.exists?('new_search_capabilities')).to be true }
  end

  describe 'names' do
    it { expect(subject.names).to eq ['filtered_options', 'new_search_capabilities'] }
  end

  describe '#set' do
    context 'when a flag is enabled' do
      before(:each) do
        subject.set('filtered_options', true)
      end

      it { expect(subject.enabled?('missing_option')).to be false }
      it { expect(subject.enabled?('filtered_options')).to be true }
      it { expect(subject.enabled?('new_search_capabilities')).to be true }
    end

    context 'when a flag is disabled' do
      before(:each) do
        subject.set('new_search_capabilities', false)
      end

      it { expect(subject.enabled?('missing_option')).to be false }
      it { expect(subject.enabled?('filtered_options')).to be false }
      it { expect(subject.enabled?('new_search_capabilities')).to be false }
    end

    context 'when the flag does not exist' do
      before(:each) do
        subject.set('missing_option', false)
      end

      it { expect(subject.enabled?('missing_option')).to be false }
      it { expect(subject.enabled?('filtered_options')).to be false }
      it { expect(subject.enabled?('new_search_capabilities')).to be true }
    end
  end
end
