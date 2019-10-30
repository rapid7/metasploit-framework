RSpec.shared_examples_for 'Msf::DBManager::Import::IP360' do
  it_should_behave_like 'Msf::DBManager::Import::IP360::ASPL'
  it_should_behave_like 'Msf::DBManager::Import::IP360::V3'
end