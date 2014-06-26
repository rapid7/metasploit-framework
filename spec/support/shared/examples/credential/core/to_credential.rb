require 'metasploit/framework/credential'

shared_examples_for 'Metasploit::Credential::Core::ToCredential' do
  context "methods" do
    context ".to_credential" do
     
      subject(:crednetial_core) do
        FactoryGirl.create(:metasploit_credential_core)
      end
      
      it { should respond_to :to_credential }
      
      it "should return a Metasploit::Framework::Credential" do
        expect {
          to_credential
        }.to be_a Metasploit::Framework::Credential
      end
      
    end
  end
end