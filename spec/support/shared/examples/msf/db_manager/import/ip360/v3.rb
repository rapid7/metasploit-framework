RSpec.shared_examples_for 'Msf::DBManager::Import::IP360::V3' do
  it { is_expected.to respond_to :import_ip360_xml_file }
  it { is_expected.to respond_to :import_ip360_xml_v3 }
end
