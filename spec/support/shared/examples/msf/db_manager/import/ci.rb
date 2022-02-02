RSpec.shared_examples_for 'Msf::DBManager::Import::CI' do
  it { is_expected.to respond_to :import_ci_noko_stream }
  it { is_expected.to respond_to :import_ci_xml }
end
