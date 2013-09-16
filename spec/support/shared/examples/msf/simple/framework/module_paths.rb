shared_examples_for 'Msf::Simple::Framework::ModulePaths' do
  let(:module_manager) do
    framework.modules
  end

	it { should be_a Msf::Simple::Framework::ModulePaths }

  context '#add_datastore_module_paths' do
    subject(:add_datastore_module_paths) do
      framework.add_datastore_module_paths
    end

    context "with datastore['MsfModulePaths']" do
      let(:datastore_module_paths) do
        2.times.collect {
          FactoryGirl.generate :metasploit_model_module_path_real_path
        }
      end

      let(:formatted_datastore_module_paths) do
        datastore_module_paths.join(';')
      end

      before(:each) do
        framework.datastore['MsfModulePaths'] = formatted_datastore_module_paths
      end

      it 'should add each path in datastore' do
        datastore_module_paths.each do |datastore_module_path|
          module_manager.should_receive(:add_path).with(
              datastore_module_path,
              hash_including(
                  prefetch: false
              )
          )
        end

        add_datastore_module_paths
      end
    end

    context "without datastore['MsfModulePaths']" do
      it 'should not add any module paths' do
        module_manager.should_not_receive(:add_path)

        add_datastore_module_paths
      end
    end
  end

  context '#add_module_paths' do
    include_context 'DatabaseCleaner'

    subject(:add_module_paths) do
      with_established_connection do
        framework.add_module_paths
      end
    end

    it 'should add datastore module paths' do
      framework.should_receive(:add_datastore_module_paths)

      add_module_paths
    end

    it 'should add named module paths' do
      framework.should_receive(:add_named_module_paths)

      add_module_paths
    end
  end

  context '#add_named_module_paths' do
    subject(:add_named_module_paths) do
      framework.add_named_module_paths
    end

    it_should_behave_like 'Msf::Simple::Framework::ModulePaths#add_named_module_paths',
                          config_directory_name: 'modules',
                          name: 'modules'

    it_should_behave_like 'Msf::Simple::Framework::ModulePaths#add_named_module_paths',
                          config_directory_name: 'user_modules',
                          name: 'user'
  end

  context '#datastore_module_paths' do
    subject(:datastore_module_paths) do
      framework.datastore_module_paths
    end

    context "with blank datastore['MsfModulePaths']" do
      it { should == [] }
    end

    context "without blank datastore['MsfModulePaths']" do
      let(:expected_datastore_module_paths) do
        2.times.collect {
          FactoryGirl.generate :metasploit_model_module_path_real_path
        }
      end

      let(:formatted_datastore_module_paths) do
        expected_datastore_module_paths.join(';')
      end

      before(:each) do
        framework.datastore['MsfModulePaths'] = formatted_datastore_module_paths
      end

      it "should split datastore value on ';'" do
        datastore_module_paths.should == expected_datastore_module_paths
      end
    end
  end

  context '#module_path_value_by_name' do
    subject(:module_path_value_by_name) do
      framework.module_path_value_by_name
    end

    it "should map 'modules' to Msf::Config.module_directory" do
      module_path_value_by_name['modules'].should == Msf::Config.module_directory
    end

    it "should map 'user' to Msf::Config.user_module_directory" do
      module_path_value_by_name['user'].should == Msf::Config.user_module_directory
    end
  end
end