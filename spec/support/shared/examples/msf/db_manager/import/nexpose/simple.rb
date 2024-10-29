RSpec.shared_examples_for 'Msf::DBManager::Import::Nexpose::Simple' do
  it { is_expected.to respond_to :import_nexpose_noko_stream }
  it { is_expected.to respond_to :import_nexpose_simplexml }
  it { is_expected.to respond_to :import_nexpose_simplexml_file }
end
