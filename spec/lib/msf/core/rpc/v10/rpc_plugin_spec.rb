# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::RPC::RPC_Plugin do
  include_context 'Msf::Simple::Framework'

  let(:service) do
    Msf::RPC::Service.new(framework)
  end

  let(:rpc) do
    described_class.new(service)
  end

  after do
    framework.plugins.dup.each { |plugin| framework.plugins.unload(plugin) }
  end

  describe '#rpc_load' do
    it 'loads a plugin from the plugin directory by name' do
      expect(rpc.rpc_load('sample')).to eq({ 'result' => 'success' })
      expect(framework.plugins.map(&:name)).to eq(['sample'])
    end

    it 'loads a plugin by path' do
      path = File.join(Msf::Config.plugin_directory, 'sample')

      expect(rpc.rpc_load(path)).to eq({ 'result' => 'success' })
      expect(framework.plugins.map(&:name)).to eq(['sample'])
    end

    it 'returns failure for a plugin that does not exist' do
      expect(rpc.rpc_load('does_not_exist')).to eq({ 'result' => 'failure' })
      expect(framework.plugins).to be_empty
    end

    it 'passes string keyed options to the plugin' do
      expect(framework.plugins).to receive(:load).with(anything, hash_including(foo: 'bar')).and_call_original

      rpc.rpc_load('sample', { 'foo' => 'bar' })
    end
  end

  describe '#rpc_unload' do
    it 'unloads a loaded plugin' do
      rpc.rpc_load('sample')

      expect(rpc.rpc_unload('sample')).to eq({ 'result' => 'success' })
      expect(framework.plugins).to be_empty
    end

    it 'returns failure when no plugin has that name' do
      expect(rpc.rpc_unload('sample')).to eq({ 'result' => 'failure' })
    end
  end

  describe '#rpc_loaded' do
    it 'returns an empty list when no plugins are loaded' do
      expect(rpc.rpc_loaded).to eq({ plugins: [] })
    end

    it 'returns the names of the loaded plugins' do
      rpc.rpc_load('sample')

      expect(rpc.rpc_loaded).to eq({ plugins: ['sample'] })
    end
  end
end
