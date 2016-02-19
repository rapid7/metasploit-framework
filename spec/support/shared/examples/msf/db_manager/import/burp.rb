RSpec.shared_examples_for 'Msf::DBManager::Import::Burp' do
  it { is_expected.to respond_to :import_burp_session_noko_stream }
  it { is_expected.to respond_to :import_burp_session_xml }
end
