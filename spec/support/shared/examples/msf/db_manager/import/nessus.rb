RSpec.shared_examples_for 'Msf::DBManager::Import::Nessus' do
  it_should_behave_like 'Msf::DBManager::Import::Nessus::NBE'
  it_should_behave_like 'Msf::DBManager::Import::Nessus::XML'
end
