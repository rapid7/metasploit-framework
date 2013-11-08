shared_examples_for 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_platforms' do
  subject(:module_platforms) do
    actual_module_instance.module_platforms
  end

  it 'should match Msf::Module#platforms' do
    expected_platform_fully_qualified_names = expected_module_instance.module_platforms.map(&:platform).map(&:fully_qualified_name)

    actual_platform_fully_qualified_names = with_established_connection {
      module_platforms.map(&:platform).map(&:fully_qualified_name)
    }

    expect(actual_platform_fully_qualified_names).to match_array(expected_platform_fully_qualified_names)
  end

  it 'should be persisted' do
    with_established_connection do
      module_platforms.all?(&:persisted?).should be_true
    end
  end
end