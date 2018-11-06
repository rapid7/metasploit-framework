RSpec.describe Metasploit::Credential::PasswordHash, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  it { is_expected.to be_a Metasploit::Credential::Private }

  context 'factories' do
    context 'metasploit_credential_password_hash' do
      subject(:metasploit_credential_password_hash) do
        FactoryBot.build(:metasploit_credential_password_hash)
      end

      it { is_expected.to be_valid }
    end
  end

  context 'validations' do
    it { is_expected.to validate_presence_of :data }
  end
end
