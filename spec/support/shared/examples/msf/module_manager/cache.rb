shared_examples_for 'Msf::ModuleManager::Cache' do
  context '#cache' do
    subject(:cache) do
      module_manager.cache
    end

    it 'should be memoized' do
      memoized = double('Metasploit::Framework::Module::Cache')
      module_manager.instance_variable_set :@cache, memoized

      cache.should == memoized
    end

    it 'should be validated' do
      Metasploit::Framework::Module::Cache.any_instance.should_receive(:valid!)

      cache
    end

    it { should be_a Metasploit::Framework::Module::Cache }

    context '#module_manager' do
      subject(:cache_module_manager) do
        cache.module_manager
      end

      it 'should be parent Msf::ModuleManager' do
        cache_module_manager.should == module_manager
      end
    end
  end
end