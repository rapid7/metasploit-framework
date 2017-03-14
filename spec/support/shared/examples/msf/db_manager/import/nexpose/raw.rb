RSpec.shared_examples_for 'Msf::DBManager::Import::Nexpose::Raw' do
  it { is_expected.to respond_to :import_nexpose_raw_noko_stream }
  it { is_expected.to respond_to :import_nexpose_rawxml }
  it { is_expected.to respond_to :import_nexpose_rawxml_file }
  it { is_expected.to respond_to :nexpose_host_from_rawxml }
  it { is_expected.to respond_to :nexpose_refs_to_struct }
end
