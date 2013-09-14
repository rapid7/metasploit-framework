shared_examples_for 'Msf::ModuleManager::ModulePaths' do
  context '#add_path' do
    include_context 'DatabaseCleaner'

    subject(:add_path) do
      with_established_connection do
        module_manager.add_path(path, options)
      end
    end

    let(:cache) do
      module_manager.cache
    end

    let(:path) do
      FactoryGirl.generate :metasploit_model_module_path_real_path
    end

    let(:path_set) do
      cache.path_set
    end

    context 'with options' do
      let(:gem) do
        'metasploit-framework'
      end

      let(:name) do
        'spec'
      end

      let(:options) do
        {
            gem: gem,
            name: name
        }
      end

      it 'should pass options to Metasploit::Framework::PathSet::Base#add' do
        path_set.should_receive(:add).with(path, options)

        add_path
      end

      it 'should prefetch added Metasploit::Model::Module::Path' do
        cache.should_receive(:prefetch) do |options|
          options.should have_key(:only)
          options[:only].should be_a Metasploit::Model::Module::Path

          # Array<Metasploit::Framework::Module::Path>
          []
        end

        add_path
      end

      it { should be_a Metasploit::Framework::Module::Path::Load }

      context 'module_path' do
        subject(:module_path) do
          add_path.module_path
        end

        it 'should have Metasploit::Model::Module::Path#gem equal to :gem option' do
          module_path.gem.should == gem
        end

        it 'should have Metasploit::Model::Module::Path#name equal to :name option' do
          module_path.name.should == name
        end

        it 'should have Metasploit::Model::Module::Path#real_path equal to path argument (converted to real path)' do
          module_path.real_path.should == path
        end
      end
    end

    context 'without options' do
      subject(:add_path) do
        with_established_connection do
          module_manager.add_path(path)
        end
      end

      it 'should default to {}' do
        path_set.should_receive(:add).with(path, {})

        add_path
      end
    end
  end
end