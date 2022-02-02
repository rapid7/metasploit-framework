RSpec.shared_examples_for 'Msf::DBManager::Import::Nessus::XML::V2' do
  it { is_expected.to respond_to :import_nessus_xml_v2 }
end