shared_examples_for 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance Mdm::Module::Instance#module_architectures' do
  subject(:module_architectures) do
    actual_module_instance.module_architectures
  end

  it 'should match Msf::Module#architectures' do
    # architectures are all seeded, so can compare records directly and not by attribute Hash
    expected_architectures = expected_module_instance.module_architectures.map(&:architecture)
    actual_architectures = module_architectures.map(&:architecture)

    expect(actual_architectures).to match_array(expected_architectures)
  end

  it 'should be persisted' do
    module_architectures.all?(&:persisted?).should be_true
  end
end