# -*- coding:binary -*-

require 'spec_helper'
require 'tmpdir'

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

  describe '#save_config with a transient read error' do
    it 'propagates the first read failure without replacing existing preferences' do
      Dir.mktmpdir do |directory|
        config = Msf::Config.new
        config['ConfigDirectory'] = directory
        path = config.config_file
        original = "[framework/features]\nmissing_feature=true\n"
        File.write(path, original)
        allow(Msf::Config).to receive(:new).and_return(config)

        read_error = Errno::EIO.new(path)
        first_read = true
        allow(IO).to receive(:readlines).and_call_original
        allow(IO).to receive(:readlines).with(path).and_wrap_original do |read, *args|
          if first_read
            first_read = false
            raise read_error
          end

          read.call(*args)
        end

        aggregate_failures do
          expect { subject.save_config }.to raise_error(Errno::EIO) { |error| expect(error).to equal(read_error) }
          expect(File.binread(path)).to eq(original)
        end
      end
    end
  end

  describe '#save_config' do
    around do |example|
      Dir.mktmpdir do |directory|
        @config_directory = directory
        example.run
      end
    end

    before do
      config_instance = Msf::Config.new
      config_instance['ConfigDirectory'] = @config_directory
      File.write(config_instance.config_file, config)
      allow(Msf::Config).to receive(:new).and_return(config_instance)
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

      it { expect(Msf::Config.load).to eq(expected_config) }
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

      it { expect(Msf::Config.load).to eq(expected_config) }
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

      it { expect(Msf::Config.load).to eq(expected_config) }
    end
  end
end
