RSpec.shared_examples_for 'Msf::DBManager::Import::Retina' do
  it { is_expected.to respond_to :import_retina_xml }
  it { is_expected.to respond_to :import_retina_xml_file }
end
