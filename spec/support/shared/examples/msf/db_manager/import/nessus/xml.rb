shared_examples_for 'Msf::DBManager::Import::Nessus::XML' do
  it { is_expected.to respond_to :import_nessus_xml_file }
end
