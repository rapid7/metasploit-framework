# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::FeatureManager do
  let(:mock_features) do
    [
      {
        name: 'filtered_options',
        description: 'Add option filtering functionality to Metasploit',
        default_value: false
      },
      {
        name: 'new_search_capabilities',
        description: 'Add new search capabilities to Metasploit',
        default_value: true
      }
    ]
  end
  let(:subject) { described_class.send(:new) }

  before(:each) do
    stub_const('Msf::FeatureManager::DEFAULTS', mock_features)
  end

  describe '#all' do
    let(:expected_features) do
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
    it { expect(subject.all).to eql expected_features }
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

  describe "#load_config" do
    before(:each) do
      allow(Msf::Config).to receive(:load).and_return(Rex::Parser::Ini.from_s(config))
      subject.load_config
    end

    context 'when the config file is empty' do
      let(:config) do
        <<~CONFIG

        CONFIG
      end

      let(:expected_features) do
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

      it { expect(subject.all).to eql expected_features }
    end

    context 'when there are valid and invalid flags' do
      let(:config) do
        <<~CONFIG
          [framework/features]
          new_search_capabilities=false
          missing_feature=true
        CONFIG
      end

      let(:expected_features) do
        [
          {
            name: 'filtered_options',
            description: 'Add option filtering functionality to Metasploit',
            enabled: false
          },
          {
            name: 'new_search_capabilities',
            description: 'Add new search capabilities to Metasploit',
            enabled: false
          }
        ]
      end

      it { expect(subject.all).to eql expected_features }
    end
  end

  describe '#save_config' do
    before(:each) do
      allow(Msf::Config).to receive(:load).and_return(Rex::Parser::Ini.from_s(config))
      allow(Msf::Config).to receive(:save)
    end

    context 'when there is no existing configuration' do
      before(:each) do
        subject.save_config
      end

      let(:config) do
        <<~CONFIG
          [framework/features]
        CONFIG
      end

      let(:expected_config) do
        {
          "framework/features" => {}
        }
      end

      it { expect(Msf::Config).to have_received(:save).with(expected_config) }
    end

    context 'when there is only a missing feature' do
      before(:each) do
        subject.save_config
      end

      let(:config) do
        <<~CONFIG
          [framework/features]
          missing_feature=true
        CONFIG
      end

      let(:expected_config) do
        {
          "framework/features" => { "missing_feature" => "true" }
        }
      end

      it { expect(Msf::Config).to have_received(:save).with(expected_config) }
    end

    context 'when there are user preferences set' do
      before(:each) do
        subject.set('new_search_capabilities', true)
        subject.save_config
      end

      let(:config) do
        <<~CONFIG
          [framework/features]
          new_search_capabilities=false
          missing_feature=true
        CONFIG
      end

      let(:expected_config) do
        {
          "framework/features" => { "missing_feature" => "true", "new_search_capabilities"=>"true" }
        }
      end

      it { expect(Msf::Config).to have_received(:save).with(expected_config) }
    end
  end
end
