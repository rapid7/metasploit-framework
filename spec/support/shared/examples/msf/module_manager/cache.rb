RSpec.shared_examples_for 'Msf::ModuleManager::Cache' do

  # Wait for data to be loaded
  before(:all) do
    Msf::Modules::Metadata::Cache.instance.get_metadata
  end

  let(:parent_path) do
    parent_pathname.to_path
  end

  let(:metadata_cache) do
    Msf::Modules::Metadata::Cache.instance
  end

  let(:parent_pathname) do
    Metasploit::Framework.root.join('modules')
  end

  let(:reference_name) do
    'windows/smb/ms08_067_netapi'
  end

  let(:type) do
    'exploit'
  end

  let(:path) do
    pathname.to_path
  end

  let(:pathname) do
    parent_pathname.join(
        'exploits',
        "#{reference_name}.rb"
    )
  end

  let(:pathname_modification_time) do
    pathname.mtime
  end

  context '#cache_empty?' do
    subject(:cache_empty?) do
      module_manager.cache_empty?
    end

    before(:example) do
      module_manager.send(:module_info_by_path=, module_info_by_path)
    end

    context 'with empty' do
      let(:module_info_by_path) do
        {}
      end

      it { is_expected.to be_truthy }
    end

    context 'without empty' do
      let(:module_info_by_path) do
        {
            'path/to/module' => {}
        }
      end

      it { is_expected.to be_falsey }
    end
  end

  context '#cache_in_memory' do
    def cache_in_memory
      module_manager.cache_in_memory(
          class_or_module,
          :path => path,
          :reference_name => reference_name,
          :type => type
      )
    end

    def module_info_by_path
      module_manager.send(:module_info_by_path)
    end

    let(:class_or_module) do
      double('Class<Msf::Module> or Module', :parent => namespace_module)
    end

    let(:namespace_module) do
      double('Msf::Modules::Namespace', :parent_path => parent_path)
    end

    context 'with existing :path' do
      it 'should update module_info_by_path' do
        expect {
          cache_in_memory
        }.to change { module_info_by_path }
      end

      context 'module_info_by_path' do
        subject(:module_info_by_path) do
          module_manager.send(:module_info_by_path)
        end

        before(:example) do
          cache_in_memory
        end

        it 'should have entry for path' do
          expect(module_info_by_path[path]).to be_a Hash
        end

        context 'value' do
          subject(:value) do
            module_info_by_path[path]
          end

          it 'should have modification time of :path option for :modification_time' do
            expect(value[:modification_time]).to eq pathname_modification_time
          end

          it 'should have parent path from namespace module for :parent_path' do
            expect(value[:parent_path]).to eq namespace_module.parent_path
          end

          it 'should use :reference_name option' do
            expect(value[:reference_name]).to eq reference_name
          end

          it 'should use :type option' do
            expect(value[:type]).to eq type
          end
        end
      end
    end

    context 'without existing :path' do
      let(:path) do
        'non/existent/path'
      end

      it 'should not raise error' do
        expect {
          cache_in_memory
        }.to_not raise_error
      end

      it 'should not update module_info_by_path' do
        expect {
          cache_in_memory
        }.to_not change { module_info_by_path }
      end
    end
  end

  context '#load_cached_module' do
    subject(:load_cached_module) do
      module_manager.load_cached_module(type, reference_name)
    end

    before(:example) do
      module_manager.send(:module_info_by_path=, module_info_by_path)
    end

    context 'with module info in cache' do
      include_context 'Metasploit::Framework::Spec::Constants cleaner'

      let(:module_info_by_path) do
        {
            'path/to/module' => {
                :parent_path => parent_path,
                :reference_name => reference_name,
                :type => type
            }
        }
      end

      it 'should enumerate loaders until if it find the one where loadable?(parent_path) is true' do
        # Only the first one gets it since it finds the module
        loader = module_manager.send(:loaders).first
        expect(loader).to receive(:loadable?).with(parent_path).and_call_original

        load_cached_module
      end

      it 'should force load using #load_module on the loader' do
        expect_any_instance_of(Msf::Modules::Loader::Directory).to receive(
            :load_module
        ).with(
            parent_path,
            type,
            reference_name,
            :force => true
        ).and_call_original

        load_cached_module
      end

      context 'return from load_module' do
        before(:example) do
          # Only the first one gets it since it finds the module
          loader = module_manager.send(:loaders).first
          expect(loader).to receive(:load_module).and_return(module_loaded)
        end

        context 'with false' do
          let(:module_loaded) do
            false
          end

          it { is_expected.to be_falsey }
        end

        context 'with true' do
          let(:module_loaded) do
            true
          end

          it { is_expected.to be_truthy }
        end
      end
    end

    context 'without module info in cache' do
      let(:module_info_by_path) do
        {}
      end

      it { is_expected.to be_falsey }
    end
  end

  context '#refresh_cache_from_module_files' do

    context 'with module argument' do
      def refresh_cache_from_module_files
        module_manager.refresh_cache_from_module_files(module_class_or_instance)
      end

      let(:module_class_or_instance) do
        Class.new(Msf::Module)
      end

      it 'should update store and then update in-memory cache from the store for the given module_class_or_instance' do
        expect(metadata_cache).to receive(:refresh_metadata_instance).with(module_class_or_instance).ordered
        expect(module_manager).to receive(:refresh_cache_from_database).ordered

        refresh_cache_from_module_files
      end
    end

    context 'without module argument' do
      def refresh_cache_from_module_files
        module_manager.refresh_cache_from_module_files
      end

      it 'should update store and then update in-memory cache from the store for all modules' do
        expect(metadata_cache).to receive(:refresh_metadata).ordered
        expect(module_manager).to receive(:refresh_cache_from_database)

        refresh_cache_from_module_files
      end
    end

  end

  context '#refresh_cache_from_database' do
    def refresh_cache_from_database
      module_manager.refresh_cache_from_database
    end

    it 'should call #module_info_by_path_from_database!' do
      expect(module_manager).to receive(:module_info_by_path_from_database!)

      refresh_cache_from_database
    end
  end


  context '#module_info_by_path' do
    it 'should have protected method module_info_by_path' do
      expect(subject.respond_to?(:module_info_by_path, true)).to be_truthy
    end
  end

  context '#module_info_by_path=' do
    it 'should have protected method module_info_by_path=' do
      expect(subject.respond_to?(:module_info_by_path=, true)).to be_truthy
    end
  end

  context '#module_info_by_path_from_database!' do
    def module_info_by_path
      module_manager.send(:module_info_by_path)
    end

    def module_info_by_path_from_database!
      module_manager.send(:module_info_by_path_from_database!)
    end

    it 'should call get metadata' do
      allow(metadata_cache).to receive(:get_metadata).and_return([])
      expect(metadata_cache).to receive(:get_metadata)

      module_info_by_path_from_database!
    end

    context 'with database cache' do
      #
      # Let!s (let + before(:each))
      #

      let!(:mdm_module_detail) do
        FactoryBot.create(:mdm_module_detail,
                           :file => path,
                           :mtype => type,
                           :mtime => pathname.mtime,
                           :refname => reference_name
        )
      end

      it 'should create cache entry for path' do
        module_info_by_path_from_database!

        expect(module_info_by_path).to have_key(path)
      end

      context 'cache entry' do
        subject(:cache_entry) do
          module_info_by_path[path]
        end

        before(:example) do
          module_info_by_path_from_database!
        end

        it { expect(subject[:modification_time]).to be_within(1.second).of(pathname_modification_time) }
        it { expect(subject[:parent_path]).to eq(parent_path) }
        it { expect(subject[:reference_name]).to eq(reference_name) }
        it { expect(subject[:type]).to eq(type) }
      end

      context 'typed module set' do
        let(:typed_module_set) do
          module_manager.module_set(type)
        end

        context 'with reference_name' do
          before(:example) do
            typed_module_set[reference_name] = double('Msf::Module')
          end

          it 'should not change reference_name value' do
            expect {
              module_info_by_path_from_database!
            }.to_not change {
              typed_module_set[reference_name]
            }
          end
        end

        context 'without reference_name' do
          it 'should set reference_name value to Msf::SymbolicModule' do
            module_info_by_path_from_database!

            # have to use fetch because [] will trigger de-symbolization and
            # instantiation.
            expect(typed_module_set.fetch(reference_name)).to eq Msf::SymbolicModule
          end
        end
      end
    end

  end
end
