# frozen_string_literal: true

require 'msf/core/mcp'
require 'tempfile'
require 'json'

RSpec.describe 'Msf::MCP log constants' do
  describe 'LOG_SOURCE' do
    it 'is set to mcp' do
      expect(Msf::MCP::LOG_SOURCE).to eq('mcp')
    end
  end

  describe 'LOG_LEVEL constants' do
    it 'maps LOG_DEBUG to LEV_3' do
      expect(Msf::MCP::LOG_DEBUG).to eq(Rex::Logging::LEV_3)
    end

    it 'maps LOG_INFO to LEV_2' do
      expect(Msf::MCP::LOG_INFO).to eq(Rex::Logging::LEV_2)
    end

    it 'maps LOG_WARN to LEV_1' do
      expect(Msf::MCP::LOG_WARN).to eq(Rex::Logging::LEV_1)
    end

    it 'maps LOG_ERROR to LEV_0' do
      expect(Msf::MCP::LOG_ERROR).to eq(Rex::Logging::LEV_0)
    end
  end

  describe 'explicit source and level usage' do
    let(:log_file) { Tempfile.new(['log_constants_test', '.log']).tap(&:close).path }
    let(:log_source) { Msf::MCP::LOG_SOURCE }

    before do
      deregister_log_source(log_source) if log_source_registered?(log_source)
      register_log_source(log_source, Msf::MCP::Logging::Sinks::JsonFlatfile.new(log_file), Rex::Logging::LEV_3)
    end

    after do
      deregister_log_source(log_source) if log_source_registered?(log_source)
      File.delete(log_file) if File.exist?(log_file)
    end

    def last_log_entry
      JSON.parse(File.read(log_file).strip.split("\n").last)
    end

    it 'routes messages to the mcp source when passed explicitly' do
      ilog('info message', log_source, Msf::MCP::LOG_INFO)
      expect(last_log_entry['message']).to include('info message')
      expect(last_log_entry['severity']).to eq('INFO')
    end

    it 'does not affect the default core source' do
      ilog('core message')
      expect(File.read(log_file)).to be_empty
    end

    it 'filters messages below the registered threshold' do
      deregister_log_source(log_source)
      register_log_source(log_source, Msf::MCP::Logging::Sinks::JsonFlatfile.new(log_file), Rex::Logging::LEV_1)

      dlog('should be filtered', log_source, Msf::MCP::LOG_DEBUG)
      expect(File.read(log_file)).to be_empty

      wlog('should appear', log_source, Msf::MCP::LOG_WARN)
      expect(File.read(log_file)).not_to be_empty
    end
  end
end
