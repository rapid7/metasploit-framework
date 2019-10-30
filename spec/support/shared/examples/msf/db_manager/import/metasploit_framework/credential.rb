RSpec.shared_examples_for 'Msf::DBManager::Import::MetasploitFramework::Credential' do
  it { is_expected.to respond_to :import_msf_cred_dump }
  it { is_expected.to respond_to :import_msf_cred_dump_zip }
  it { is_expected.to respond_to :import_msf_pwdump }
end
