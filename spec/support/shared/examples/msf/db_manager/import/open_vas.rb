RSpec.shared_examples_for 'Msf::DBManager::Import::OpenVAS' do
  it { is_expected.to respond_to :import_openvas_new_xml }
  it { is_expected.to respond_to :import_openvas_new_xml_file }
  it { is_expected.to respond_to :import_openvas_xml }
end
