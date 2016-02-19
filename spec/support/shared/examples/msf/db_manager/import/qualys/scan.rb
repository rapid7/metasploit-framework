RSpec.shared_examples_for 'Msf::DBManager::Import::Qualys::Scan' do
  it { is_expected.to respond_to :import_qualys_scan_xml }
  it { is_expected.to respond_to :import_qualys_scan_xml_file }
end
