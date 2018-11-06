RSpec.describe Metasploit::Credential::Importer::Pwdump do


  let(:workspace) {FactoryBot.create(:mdm_workspace)}
  let(:origin) { FactoryBot.create(:metasploit_credential_origin_import) }

  subject(:pwdump_importer){ FactoryBot.build(:metasploit_credential_importer_pwdump,
                                               workspace: workspace,
                                               origin: origin)}

  describe "validation" do
    it { is_expected.to be_valid }

    describe "without a filename" do
      it 'should not be valid' do
        pwdump_importer.filename = nil
        expect(pwdump_importer).not_to be_valid
      end
    end
  end

  describe "#blank_or_string" do
    context "with a blank string" do
      it 'should return empty string' do
        expect(pwdump_importer.blank_or_string("")).to eq("")
      end
    end
    context "with a BLANK_CRED_STRING" do
      it 'should return empty string' do
        expect(pwdump_importer.blank_or_string(Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING)).to eq("")
      end
    end

    context "with a JTR_NO_PASSWORD_STRING" do
      it 'should return empty string' do
        expect(pwdump_importer.blank_or_string(Metasploit::Credential::Importer::Pwdump::JTR_NO_PASSWORD_STRING)).to eq("")
      end
    end

    context "with a present string" do
      it 'should return the string' do
        string = "mah-hard-passwerd"
        expect(pwdump_importer.blank_or_string(string)).to eq(string)
      end
    end

    context "with the dehex flag" do
      it 'should dehex the string with the Metasploit::Credential::Text#dehex method' do
        string = "mah-hard-passwerd"
        expect(Metasploit::Credential::Text).to receive(:dehex).with string
        pwdump_importer.blank_or_string(string, true)
      end
    end
  end

  describe "#import!" do
    describe "creating Credential objects" do
      it 'should create the proper number of Cores' do
        expect{pwdump_importer.import!}.to change(Metasploit::Credential::Core, :count).from(0).to(6)
      end

      it 'should create Cores with the same Origin' do
        pwdump_importer.import!
        origins = Metasploit::Credential::Core.all.collect(&:origin).uniq
        expect(origins.size).to be(1)
        expect(origins.first.id).to be(origin.id)
      end

      it 'should create the proper number of Logins' do
        expect{pwdump_importer.import!}.to change(Metasploit::Credential::Login, :count).from(0).to(6)
      end

      it 'should create the proper number of Publics' do
        expect{pwdump_importer.import!}.to change(Metasploit::Credential::Public, :count).from(0).to(2)
      end

      describe 'should create the proper number of Privates' do
        it 'should create 1 NTLM hash' do
          expect{pwdump_importer.import!}.to change(Metasploit::Credential::NTLMHash, :count).from(0).to(1)
        end

        it 'should create 2 NonreplayableHashes' do
          expect{pwdump_importer.import!}.to change(Metasploit::Credential::NonreplayableHash, :count).from(0).to(2)
        end

        it 'should create 2 Passwords' do
          expect{pwdump_importer.import!}.to change(Metasploit::Credential::Password, :count).from(0).to(2)
        end

        it 'creates 1 PostgresMD5' do
          expect{pwdump_importer.import!}.to change(Metasploit::Credential::PostgresMD5, :count).from(0).to(1)
        end

        # Legacy files may have these lines when missing SSH key files
        it 'should not create a Private from a "Warning" line' do
          pwdump_importer.import!
          expect(Metasploit::Credential::Private.where(data:'missing')).to be_blank
        end
      end
    end

    describe "creating Host objects" do
      it 'should create the proper number of Hosts' do
        expect{pwdump_importer.import!}.to change(Mdm::Host, :count).from(0).to(2)
      end
    end

    describe "creating Service objects" do
      it 'should create the proper number of Services' do
        expect{pwdump_importer.import!}.to change(Mdm::Service, :count).from(0).to(3)
      end
    end

  end
  
end