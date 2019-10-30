RSpec.shared_examples_for 'Msf::DBManager::Import::IP360::ASPL' do
  it { is_expected.to respond_to :import_ip360_aspl_xml }
end
