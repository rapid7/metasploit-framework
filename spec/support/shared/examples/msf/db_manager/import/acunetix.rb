RSpec.shared_examples_for 'Msf::DBManager::Import::Acunetix' do
  it { is_expected.to respond_to :import_acunetix_noko_stream }
  it { is_expected.to respond_to :import_acunetix_xml }
end
