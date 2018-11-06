RSpec.describe Mdm::Session, type: :model do
  context 'associations' do
    it { is_expected.to have_many(:credential_origins).class_name('Metasploit::Credential::Origin::Session').dependent(:destroy) }
  end
end