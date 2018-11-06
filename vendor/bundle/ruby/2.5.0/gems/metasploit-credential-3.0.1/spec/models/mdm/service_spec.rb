RSpec.describe Mdm::Service, type: :model do
  context 'associations' do
    it { is_expected.to have_many(:credential_origins).class_name('Metasploit::Credential::Origin::Service').dependent(:destroy) }
    it { is_expected.to have_many(:logins).class_name('Metasploit::Credential::Login').dependent(:destroy) }
  end
end