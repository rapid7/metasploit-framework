RSpec.describe Metasploit::Credential::Password, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  it { is_expected.to be_a Metasploit::Credential::Private }

  context 'factories' do
    context 'metasploit_credential_password' do
      subject(:metasploit_credential_password) do
        FactoryBot.build(:metasploit_credential_password)
      end

      it { is_expected.to be_valid }
    end
  end
end
