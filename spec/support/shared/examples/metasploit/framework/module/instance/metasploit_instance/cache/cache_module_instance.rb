shared_examples_for 'Metasploit::Framework::Module::Instance::MetasploitInstance::Cache#cache_module_instance' do
  it 'should create Mdm::Module::Instance' do
    expect {
      cache_module_instance
    }.to change {
      with_established_connection {
        Mdm::Module::Instance.count
      }
    }.by(1)
  end
end