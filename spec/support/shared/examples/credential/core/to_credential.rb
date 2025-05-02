require 'metasploit/framework/credential'

RSpec.shared_examples_for 'Metasploit::Credential::Core::ToCredential' do
  context "methods" do
    context ".to_credential" do
      let!(:origin) { FactoryBot.create(:metasploit_credential_origin_import) }
      let!(:workspace) { FactoryBot.create(:mdm_workspace) }


      subject(:credential_core) do
        FactoryBot.create(:metasploit_credential_core,
                          origin: origin,
                          workspace: workspace)
      end

      it { is_expected.to respond_to :to_credential }

      it "should return a Metasploit::Framework::Credential" do
        expect(
          credential_core.to_credential
        ).to be_a Metasploit::Framework::Credential
      end

      it "should set the parent to the credential object" do
        expect(
          credential_core.to_credential.parent
        ).to eq(credential_core)
      end
    end
  end
end
