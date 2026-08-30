RSpec.shared_examples_for 'Msf::DBManager::Import::Nessus::XML::V1' do
  it { is_expected.to respond_to :import_nessus_xml }
end