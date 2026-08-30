require 'spec_helper'

RSpec.describe Msf::ModuleSet do
  subject(:module_set) do
    described_class.new(module_type)
  end

  let(:module_type) do
    FactoryBot.generate :mdm_module_detail_mtype
  end

  describe '#rank_modules' do
    subject(:rank_modules) do
      module_set.send(:rank_modules)
    end

    let(:module_metadata_a) do
      instance_double(Msf::Modules::Metadata::Obj)
    end

    let(:module_metadata_b) do
      instance_double(Msf::Modules::Metadata::Obj)
    end

    let(:module_metadata_c) do
      instance_double(Msf::Modules::Metadata::Obj)
    end

    let(:module_metadata) do
      {
        'a' => module_metadata_a,
        'b' => module_metadata_b,
        'c' => module_metadata_c
      }
    end

    context 'with loaded modules' do
      #
      # lets
      #

      let(:a_class) do
        Class.new
      end

      let(:b_class) do
        Class.new
      end

      let(:c_class) do
        Class.new
      end

      #
      # Callbacks
      #

      before(:example) do
        module_set['a'] = a_class
        module_set['b'] = b_class
        module_set['c'] = c_class
      end

      context 'with Rank' do
        before(:example) do
          allow(module_metadata_a).to receive(:rank).and_return(Msf::LowRanking)
          allow(module_metadata_b).to receive(:rank).and_return(Msf::AverageRanking)
          allow(module_metadata_c).to receive(:rank).and_return(Msf::GoodRanking)
          allow(Msf::Modules::Metadata::Cache.instance).to receive(:module_metadata).with(anything).and_return(module_metadata)
        end

        it 'is ranked using Rank' do
          expect(rank_modules).to eq(
            [
              ['c', module_metadata_c],
              ['b', module_metadata_b],
              ['a', module_metadata_a]
            ]
          )
        end
      end

      context 'without Rank' do
        before(:example) do
          allow(module_metadata_a).to receive(:rank).and_return(nil)
          allow(module_metadata_b).to receive(:rank).and_return(Msf::AverageRanking)
          allow(module_metadata_c).to receive(:rank).and_return(Msf::GoodRanking)
          allow(Msf::Modules::Metadata::Cache.instance).to receive(:module_metadata).with(anything).and_return(module_metadata)
        end

        it 'is ranked as Normal' do
          expect(rank_modules).to eq(
            [
              ['c', module_metadata_c],
              ['a', module_metadata_a],
              ['b', module_metadata_b]
            ]
          )
        end
      end
    end

    context 'with the same rank' do
      before(:example) do
        allow(module_metadata_a).to receive(:rank).and_return(Msf::AverageRanking)
        allow(module_metadata_b).to receive(:rank).and_return(Msf::AverageRanking)
        allow(module_metadata_c).to receive(:rank).and_return(Msf::AverageRanking)
        allow(Msf::Modules::Metadata::Cache.instance).to receive(:module_metadata).with(anything).and_return(module_metadata)
      end

      it 'ranks the modules consistently' do
        expect(rank_modules).to eq(
          [
            ['c', module_metadata_c],
            ['b', module_metadata_b],
            ['a', module_metadata_a]
          ]
        )
      end
    end
  end

  describe '#[]' do
    let(:module_refname) { 'module_refname' }
    let(:framework) { instance_double(Msf::Framework) }
    let(:module_manager) { instance_double(Msf::ModuleManager) }
    let(:cache_type) { Msf::ModuleManager::Cache::FILESYSTEM }

    before(:each) do
      allow(subject).to receive(:create).with(module_refname)
      allow(subject).to receive(:framework).and_return(framework)
      allow(framework).to receive(:modules).and_return(module_manager)
      allow(module_manager).to receive(:load_cached_module)
    end

    context 'when the module set is empty' do
      it 'loads the module class from the cache' do
        subject[module_refname]
        is_expected.not_to have_received(:create).with(module_refname)
        expect(module_manager).to have_received(:load_cached_module).with(module_type, module_refname, cache_type: cache_type)
      end
    end

    context 'when the module set has symbolic modules' do
      before(:each) do
        subject[module_refname] = nil
      end
      it 'attempts to create the module' do
        subject[module_refname]
        is_expected.not_to have_received(:create).with(module_refname)
        expect(module_manager).to have_received(:load_cached_module).with(module_type, module_refname, cache_type: cache_type)
      end
    end

    context 'when a module is contained within the set' do
      let(:stored_module) { double('module') }
      before(:each) do
        subject[module_refname] = stored_module
      end
      it 'does not attempt to create the module' do
        expect(subject[module_refname]).to be(stored_module)
        is_expected.not_to have_received(:create).with(module_refname)
        expect(module_manager).not_to have_received(:load_cached_module)
      end
    end
  end

  describe '#fetch' do
    let(:module_refname) { 'module_refname' }

    context 'when the module set is empty' do
      before(:each) do
        allow(subject).to receive(:create).with(module_refname)
      end

      # TODO: it's unexpected that `fetch` and `[]` would act this differently
      # investigate implementing `to_hash` to tell ruby we act like a hash over extending Hash
      # seems like this is potentially a feature not a bug, we use `fetch` to intentionally not create modules sometimes
      xit 'attempts to create the module' do
        subject.fetch(module_refname)
        is_expected.to have_received(:create).with(module_refname)
      end
    end
  end

  describe '#create' do
    let(:module_refname) { 'module_refname' }
    let(:framework) { instance_double(Msf::Framework) }
    let(:module_manager) { instance_double(Msf::ModuleManager) }
    let(:events) { double('events') }
    let(:cache_type) { Msf::ModuleManager::Cache::FILESYSTEM }

    before(:each) do
      allow(subject).to receive(:framework).and_return(framework)
      allow(framework).to receive(:modules).and_return(module_manager)
      allow(framework).to receive(:events).and_return(events)
      allow(events).to receive(:on_module_created)
    end

    context 'when module set is empty' do
      context 'when the module cannot be loaded' do
        before(:each) do
          allow(subject).to receive(:fetch).and_return(nil)
          allow(subject).to receive(:delete)
          allow(module_manager).to receive(:load_cached_module)
        end

        it 'fails to create the module' do
          subject.create(module_refname, cache_type: cache_type)
          expect(subject).to have_received(:fetch).with(module_refname, nil).twice
          expect(subject).to have_received(:delete).with(module_refname)
          expect(module_manager).to have_received(:load_cached_module).with(module_type, module_refname, cache_type: cache_type)
          expect(events).not_to have_received(:on_module_created)
        end
      end

      context 'when the module can be loaded' do
        let(:loaded_module) { instance_double(Class) }
        let(:module_instance) { Class.new }

        before(:each) do
          allow(subject).to receive(:fetch).and_return(nil, loaded_module)
          allow(subject).to receive(:delete)
          allow(module_manager).to receive(:load_cached_module)
          allow(loaded_module).to receive(:new).and_return(module_instance)
        end

        it 'creates the module' do
          expect(subject.create(module_refname, cache_type: cache_type)).to be(module_instance)
          expect(subject).to have_received(:fetch).with(module_refname, nil).twice
          expect(subject).not_to have_received(:delete).with(module_refname)
          expect(module_manager).to have_received(:load_cached_module).with(module_type, module_refname, cache_type: cache_type)
          expect(events).to have_received(:on_module_created).with(module_instance)
        end
      end
    end
  end
end
