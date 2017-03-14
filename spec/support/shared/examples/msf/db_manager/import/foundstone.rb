RSpec.shared_examples_for 'Msf::DBManager::Import::Foundstone' do
  it { is_expected.to respond_to :import_foundstone_noko_stream }
  it { is_expected.to respond_to :import_foundstone_xml }
end
