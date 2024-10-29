RSpec.shared_examples_for 'Msf::DBManager::Import::MetasploitFramework::Zip' do
  it { is_expected.to respond_to :import_msf_collateral }
  it { is_expected.to respond_to :import_msf_zip }
end
