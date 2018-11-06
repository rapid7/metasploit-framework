RSpec.describe Mdm::Task, type: :model do
  context 'associations' do
    it { is_expected.to have_many(:import_credential_origins).class_name('Metasploit::Credential::Origin::Import').dependent(:destroy) }
    it { is_expected.to have_and_belong_to_many(:credential_cores).class_name('Metasploit::Credential::Core') }
    it { is_expected.to have_and_belong_to_many(:credential_logins).class_name('Metasploit::Credential::Login') }
  end
end