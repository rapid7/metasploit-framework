RSpec.shared_examples_for 'Msf::DBManager::Import::Qualys' do
  it_should_behave_like 'Msf::DBManager::Import::Qualys::Asset'
  it_should_behave_like 'Msf::DBManager::Import::Qualys::Scan'
end