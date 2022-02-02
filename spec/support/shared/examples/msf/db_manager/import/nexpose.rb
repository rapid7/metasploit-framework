RSpec.shared_examples_for 'Msf::DBManager::Import::Nexpose' do
  it_should_behave_like 'Msf::DBManager::Import::Nexpose::Raw'
  it_should_behave_like 'Msf::DBManager::Import::Nexpose::Simple'
end