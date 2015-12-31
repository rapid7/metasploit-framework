RSpec.shared_examples_for 'Msf::DBManager::Import::Appscan' do
  it { is_expected.to respond_to :import_appscan_noko_stream }
  it { is_expected.to respond_to :import_appscan_xml }
end