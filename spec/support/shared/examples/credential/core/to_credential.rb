require 'metasploit/framework/credential'

RSpec.shared_examples_for 'Metasploit::Credential::Core::ToCredential' do
  context "methods" do
    context ".to_credential" do

      subject(:crednetial_core) do
        FactoryBot.create(:metasploit_credential_core)
      end

      it { is_expected.to respond_to :to_credential }

      it "should return a Metasploit::Framework::Credential" do
        expect(
          crednetial_core.to_credential
        ).to be_a Metasploit::Framework::Credential
      end

      it "should set the parent to the credential object" do
        expect(
          crednetial_core.to_credential.parent
        ).to eq(crednetial_core)
      end
    end
  end
end
