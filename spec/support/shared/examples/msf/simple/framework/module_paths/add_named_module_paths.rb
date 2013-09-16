shared_examples_for 'Msf::Simple::Framework::ModulePaths#add_named_module_paths' do |options={}|
  options.assert_valid_keys(:config_directory_name, :name)

  config_directory_name = options.fetch(:config_directory_name)
  name = options.fetch(:name)
  config_method = "#{config_directory_name}_directory".to_sym

  context config_directory_name.to_s do
    before(:each) do
      Msf::Config.stub(config_method: config_method)
    end

    context 'with present' do
      let(config_method) do
        FactoryGirl.generate :metasploit_model_module_path_real_path
      end

      it "should add gem: 'metasploit-framework', name: '#{name}'" do
        module_manager.should_not_receive(:add_path).with(
            hash_including(
                send(config_method),
                gem: 'metasploit-framework',
                name: name,
                prefetch: false
            )
        )

        add_named_module_paths
      end
    end

    context 'without present' do
      let(config_method) do
        nil
      end

      it "should not add gem: 'metasploit-framework', name: '#{name}'" do
        module_manager.should_not_receive(:add_path).with(
            hash_including(
                anything,
                gem: 'metasploit-framework',
                name: name,
                prefetch: false
            )
        )

        add_named_module_paths
      end
    end
  end
end