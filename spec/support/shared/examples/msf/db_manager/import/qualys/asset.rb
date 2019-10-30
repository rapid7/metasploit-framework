RSpec.shared_examples_for 'Msf::DBManager::Import::Qualys::Asset' do
  it { is_expected.to respond_to :find_qualys_asset_ports }
  it { is_expected.to respond_to :find_qualys_asset_vuln_refs }
  it { is_expected.to respond_to :find_qualys_asset_vulns }
  it { is_expected.to respond_to :import_qualys_asset_xml }
end
