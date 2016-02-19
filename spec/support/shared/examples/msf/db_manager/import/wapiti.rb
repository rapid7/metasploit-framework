RSpec.shared_examples_for 'Msf::DBManager::Import::Wapiti' do
  it { is_expected.to respond_to :import_wapiti_xml }
  it { is_expected.to respond_to :import_wapiti_xml_file }
end
