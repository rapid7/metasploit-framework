RSpec.shared_examples_for 'Msf::DBManager::Import::Nmap' do
  it { is_expected.to respond_to :import_nmap_noko_stream }
  it { is_expected.to respond_to :import_nmap_xml }
  it { is_expected.to respond_to :import_nmap_xml_file }
  it { is_expected.to respond_to :nmap_msf_service_map }
end
