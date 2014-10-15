shared_examples_for 'Msf::DBManager::Import::MetasploitFramework' do
  it { is_expected.to respond_to :nils_for_nulls }

  it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework::Credential'
  it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework::XML'
  it_should_behave_like 'Msf::DBManager::Import::MetasploitFramework::Zip'
end
