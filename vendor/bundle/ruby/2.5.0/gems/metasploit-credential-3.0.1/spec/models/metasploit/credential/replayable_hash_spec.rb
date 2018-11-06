RSpec.describe Metasploit::Credential::ReplayableHash, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  it { is_expected.to be_a Metasploit::Credential::PasswordHash }

  context 'factories' do
    context 'metasploit_credential_replayable_hash' do
      subject(:metasploit_credential_replayable_hash) do
        FactoryBot.build(:metasploit_credential_replayable_hash)
      end

      it { is_expected.to be_valid }
    end
  end
end
