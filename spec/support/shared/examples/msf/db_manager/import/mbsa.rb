RSpec.shared_examples_for 'Msf::DBManager::Import::MBSA' do
  it { is_expected.to respond_to :import_mbsa_noko_stream }
  it { is_expected.to respond_to :import_mbsa_xml }
end
