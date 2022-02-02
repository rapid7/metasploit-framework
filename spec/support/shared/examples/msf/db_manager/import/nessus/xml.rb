RSpec.shared_examples_for 'Msf::DBManager::Import::Nessus::XML' do
  it { is_expected.to respond_to :import_nessus_xml_file }

  it_should_behave_like 'Msf::DBManager::Import::Nessus::XML::V1'
  it_should_behave_like 'Msf::DBManager::Import::Nessus::XML::V2'
end
