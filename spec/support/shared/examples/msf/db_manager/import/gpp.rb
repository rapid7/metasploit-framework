RSpec.shared_examples_for 'Msf::DBManager::Import::GPP' do
  it { is_expected.to respond_to :import_gpp_xml }
end
