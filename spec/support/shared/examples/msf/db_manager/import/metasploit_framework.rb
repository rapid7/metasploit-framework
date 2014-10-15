shared_examples_for 'Msf::DBManager::Import::MetasploitFramework' do
  it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework::XML'
  it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework::Zip'
end
