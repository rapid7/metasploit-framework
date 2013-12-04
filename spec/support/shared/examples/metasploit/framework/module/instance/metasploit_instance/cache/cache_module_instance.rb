shared_examples_for 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance' do
  it 'should create Mdm::Module::Instance' do
    expect {
      cache_module_instance
    }.to change(Mdm::Module::Instance, :count).by(1)
  end

  it 'should use batched save' do
    module_instance.should_receive(:batched_save)

    cache_module_instance
  end

  it 'should disable unique validations' do
    ActiveRecord::Validations::UniquenessValidator.should_not_receive(:validate_each)

    cache_module_instance
  end
end