# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Modules::Metadata::Cache do
  # Build a testable Cache instance without triggering the Singleton constructor
  # (which spawns a thread and loads the store from disk).
  let(:cache) do
    obj = described_class.send(:allocate)
    obj.instance_variable_set(:@mutex, Mutex.new)
    obj.instance_variable_set(:@module_metadata_cache, {})
    obj.instance_variable_set(:@metadata_type_index, {})
    obj.instance_variable_set(:@store_loaded, true)
    obj.instance_variable_set(:@load_thread, Thread.new {})
    obj
  end

  def make_metadata(type:, ref_name:, path: '/modules/test.rb')
    Msf::Modules::Metadata::Obj.from_hash({
      'name' => ref_name,
      'fullname' => "#{type}/#{ref_name}",
      'rank' => 300,
      'type' => type,
      'author' => ['rspec'],
      'description' => 'Test module',
      'references' => [],
      'mod_time' => '2024-01-01 00:00:00 +0000',
      'path' => path,
      'is_install_path' => false,
      'ref_name' => ref_name
    })
  end

  def populate_cache(cache, *entries)
    entries.each do |entry|
      cache.instance_variable_get(:@module_metadata_cache)["#{entry.type}_#{entry.ref_name}"] = entry
    end
    cache.send(:rebuild_type_cache)
  end

  # Fake module instance for refresh_metadata_instance_internal
  def make_module_instance(type:, refname:, path: '/modules/test.rb')
    mod = double('module_instance')
    klass = double('module_class', refname: refname)
    allow(mod).to receive(:type).and_return(type)
    allow(mod).to receive(:class).and_return(klass)
    allow(mod).to receive(:refname).and_return(refname)
    allow(mod).to receive(:realname).and_return("#{type}/#{refname}")
    allow(mod).to receive(:name).and_return(refname)
    allow(mod).to receive(:aliases).and_return([])
    allow(mod).to receive(:disclosure_date).and_return(nil)
    allow(mod).to receive(:rank).and_return(300)
    allow(mod).to receive(:description).and_return('Test')
    allow(mod).to receive(:author).and_return([])
    allow(mod).to receive(:references).and_return([])
    allow(mod).to receive(:post_auth?).and_return(false)
    allow(mod).to receive(:default_cred?).and_return(false)
    allow(mod).to receive(:platform_to_s).and_return('')
    allow(mod).to receive(:platform).and_return(nil)
    allow(mod).to receive(:arch_to_s).and_return('')
    allow(mod).to receive(:datastore).and_return({})
    allow(mod).to receive(:file_path).and_return(path)
    allow(mod).to receive(:has_check?).and_return(false)
    allow(mod).to receive(:notes).and_return({})

    # Stub specific respond_to? checks used by Obj#initialize
    allow(mod).to receive(:respond_to?).with(:needs_cleanup).and_return(false)
    allow(mod).to receive(:respond_to?).with(:actions).and_return(false)
    allow(mod).to receive(:respond_to?).with(:autofilter_ports).and_return(false)
    allow(mod).to receive(:respond_to?).with(:autofilter_services).and_return(false)
    allow(mod).to receive(:respond_to?).with(:targets).and_return(false)
    allow(mod).to receive(:respond_to?).with(:session_types).and_return(false)
    allow(mod).to receive(:respond_to?).with(:payload_type).and_return(false)
    mod
  end

  describe '#module_metadata' do
    it 'returns modules of the requested type' do
      exploit = make_metadata(type: 'exploit', ref_name: 'test/vuln')
      auxiliary = make_metadata(type: 'auxiliary', ref_name: 'scanner/test', path: '/modules/aux.rb')
      populate_cache(cache, exploit, auxiliary)

      result = cache.module_metadata('exploit')
      expect(result.keys).to eq(['test/vuln'])
      expect(result['test/vuln']).to eq(exploit)
    end

    it 'returns an empty hash for unknown types' do
      exploit = make_metadata(type: 'exploit', ref_name: 'test/vuln')
      populate_cache(cache, exploit)

      expect(cache.module_metadata('post')).to eq({})
    end

    it 'returns a copy that does not affect internal state' do
      exploit = make_metadata(type: 'exploit', ref_name: 'test/vuln')
      populate_cache(cache, exploit)

      result = cache.module_metadata('exploit')
      result.delete('test/vuln')

      expect(cache.module_metadata('exploit').keys).to eq(['test/vuln'])
    end
  end

  describe '#rebuild_type_cache' do
    it 'groups all entries by type' do
      e1 = make_metadata(type: 'exploit', ref_name: 'test/a', path: '/modules/a.rb')
      e2 = make_metadata(type: 'exploit', ref_name: 'test/b', path: '/modules/b.rb')
      aux = make_metadata(type: 'auxiliary', ref_name: 'scan/c', path: '/modules/c.rb')
      populate_cache(cache, e1, e2, aux)

      expect(cache.module_metadata('exploit').size).to eq(2)
      expect(cache.module_metadata('auxiliary').size).to eq(1)
    end
  end

  describe '#refresh_metadata_instance_internal' do
    it 'adds a new module to the type index' do
      mod = make_module_instance(type: 'exploit', refname: 'test/new', path: '/modules/new.rb')
      cache.send(:rebuild_type_cache)
      cache.send(:refresh_metadata_instance_internal, mod)

      result = cache.module_metadata('exploit')
      expect(result.keys).to eq(['test/new'])
    end

    it 'updates an existing module in the type index' do
      old = make_metadata(type: 'exploit', ref_name: 'test/mod', path: '/modules/mod.rb')
      populate_cache(cache, old)

      mod = make_module_instance(type: 'exploit', refname: 'test/mod', path: '/modules/mod.rb')
      cache.send(:refresh_metadata_instance_internal, mod)

      result = cache.module_metadata('exploit')
      expect(result.size).to eq(1)
      expect(result['test/mod']).not_to eq(old)
    end

    context 'when a module changes type' do
      it 'removes the old type entry and adds to the new type' do
        # Module starts as auxiliary
        old_aux = make_metadata(type: 'auxiliary', ref_name: 'test/mistyped', path: '/modules/mistyped.rb')
        other_aux = make_metadata(type: 'auxiliary', ref_name: 'scan/other', path: '/modules/other.rb')
        populate_cache(cache, old_aux, other_aux)

        expect(cache.module_metadata('auxiliary').size).to eq(2)
        expect(cache.module_metadata('exploit')).to eq({})

        # Now refresh it as an exploit (same path, different type)
        mod = make_module_instance(type: 'exploit', refname: 'test/mistyped', path: '/modules/mistyped.rb')
        cache.send(:refresh_metadata_instance_internal, mod)

        # Old auxiliary entry should be gone, other auxiliary should remain
        aux_result = cache.module_metadata('auxiliary')
        expect(aux_result.size).to eq(1)
        expect(aux_result.keys).to eq(['scan/other'])

        # New exploit entry should exist
        exploit_result = cache.module_metadata('exploit')
        expect(exploit_result.size).to eq(1)
        expect(exploit_result.keys).to eq(['test/mistyped'])
      end

      it 'does not leave stale entries in the main cache' do
        old = make_metadata(type: 'auxiliary', ref_name: 'test/stale', path: '/modules/stale.rb')
        populate_cache(cache, old)

        mod = make_module_instance(type: 'exploit', refname: 'test/stale', path: '/modules/stale.rb')
        cache.send(:refresh_metadata_instance_internal, mod)

        main_cache = cache.instance_variable_get(:@module_metadata_cache)
        types = main_cache.values.map(&:type).uniq
        expect(types).to eq(['exploit'])
      end
    end
  end

  describe '#remove_from_cache' do
    it 'removes the named module and returns true' do
      mod = make_metadata(type: 'exploit', ref_name: 'test/remove', path: '/modules/remove.rb')
      populate_cache(cache, mod)

      result = cache.send(:remove_from_cache, 'test/remove')
      expect(result).to be true
      expect(cache.instance_variable_get(:@module_metadata_cache)).to be_empty
      expect(cache.module_metadata('exploit')).to eq({})
    end

    it 'returns false when the module does not exist' do
      result = cache.send(:remove_from_cache, 'test/nonexistent')
      expect(result).to be false
    end
  end

  describe '#get_cache_key' do
    it 'returns type_refname' do
      mod = make_module_instance(type: 'exploit', refname: 'test/key')
      expect(cache.send(:get_cache_key, mod)).to eq('exploit_test/key')
    end
  end
end
