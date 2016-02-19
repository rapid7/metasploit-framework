RSpec.shared_examples_for 'Msf::DBManager::Import::Netsparker' do
  it { is_expected.to respond_to :import_netsparker_xml }
  it { is_expected.to respond_to :import_netsparker_xml_file }
  it { is_expected.to respond_to :netsparker_method_map }
  it { is_expected.to respond_to :netsparker_params_map }
  it { is_expected.to respond_to :netsparker_pname_map }
  it { is_expected.to respond_to :netsparker_vulnerability_map }
end