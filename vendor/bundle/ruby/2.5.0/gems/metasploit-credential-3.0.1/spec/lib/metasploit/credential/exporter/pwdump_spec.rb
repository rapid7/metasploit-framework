RSpec.describe Metasploit::Credential::Exporter::Pwdump do


  subject(:exporter){ Metasploit::Credential::Exporter::Pwdump.new}

  let(:public) { FactoryBot.create(:metasploit_credential_username)}
  let(:core){ FactoryBot.create :metasploit_credential_core, public: public }
  let(:login){ FactoryBot.create(:metasploit_credential_login, core: core) }

  describe "formatting" do
    describe "associated Mdm::Service objects" do
      it 'should properly format the service information' do
        service = login.service
        expect(exporter.format_service_for_login(login)).to eq "#{service.host.address.to_s}:#{service.port}/#{service.proto} (#{service.name})"
      end
    end

    describe "plaintext passwords" do
      let(:private){ FactoryBot.build :metasploit_credential_password }

      before(:example) do
        core.private = private
      end

      it 'should have the proper formatting with extant data' do
        expect(exporter.format_password(login)).to eq("#{login.core.public.username} #{login.core.private.data}")
      end

      it 'should have the proper formatting with a missing public' do
        login.core.public.username = ""
        expect(exporter.format_password(login)).to eq("#{Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING} #{login.core.private.data}")
      end

      it 'should have the proper formatting with a missing private' do
        login.core.private.data = ""
        expect(exporter.format_password(login)).to eq("#{login.core.public.username} #{Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING}")
      end
    end

    describe "non-replayable" do
      let(:private){ FactoryBot.build :metasploit_credential_nonreplayable_hash }

      before(:example) do
        core.private = private
      end

      it 'should have the proper formatting with extant data' do
        expect(exporter.format_nonreplayable_hash(login)).to eq("#{login.core.public.username}:#{login.core.private.data}:::")
      end

      it 'should have the proper formatting with a missing public' do
        login.core.public.username = ""
        expect(exporter.format_nonreplayable_hash(login)).to eq("#{Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING}:#{login.core.private.data}:::")
      end

      it 'should have the proper formatting with a missing private' do
        login.core.private.data = ""
        expect(exporter.format_nonreplayable_hash(login)).to eq("#{login.core.public.username}:#{Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING}:::")
      end
    end

    describe "NTLM" do
      let(:private){ FactoryBot.build :metasploit_credential_ntlm_hash }

      before(:example) do
        core.private = private
      end

      it 'should have the proper formatting with extant data' do
        expect(exporter.format_ntlm_hash(login)).to eq("#{login.core.public.username}:#{login.id}:#{login.core.private.data}:::")
      end

      it 'should have the proper formatting with a missing public' do
        login.core.public.username = ""
        expect(exporter.format_ntlm_hash(login)).to eq("#{Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING}:#{login.id}:#{login.core.private.data}:::")
      end

      it 'should have the proper formatting with a missing private' do
        login.core.private.data = ""
        expect(exporter.format_ntlm_hash(login)).to eq("#{login.core.public.username}:#{login.id}:#{Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING}:::")
      end
    end

    describe "PostgresMD5" do
      let(:private){ FactoryBot.build :metasploit_credential_postgres_md5 }

      before(:example) do
        core.private = private
      end

      it 'should have the proper formatting with extant data' do
        expect(exporter.format_postgres_md5(login)).to eq("#{login.core.public.username}:#{login.core.private.data}")
      end

      it 'should have the proper formatting with a missing public' do
        login.core.public.username = ""
        expect(exporter.format_postgres_md5(login)).to eq("#{Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING}:#{login.core.private.data}")
      end

      it 'should have the proper formatting with a missing private' do
        login.core.private.data = ""
        expect(exporter.format_postgres_md5(login)).to eq("#{login.core.public.username}:#{Metasploit::Credential::Exporter::Pwdump::BLANK_CRED_STRING}")
      end

    end

    describe "SMB net hashes" do
      describe "v1" do
        describe "netlm" do
          let(:private){ FactoryBot.build :metasploit_credential_nonreplayable_hash, jtr_type: 'netlm' }

          before(:example) do
            core.private = private
          end

          it 'should have the proper formatting with extant data'
          it 'should have the proper formatting with a missing public'
          it 'should have the proper formatting with a missing private'
        end

        describe "netntlm" do
          let(:private){ FactoryBot.build :metasploit_credential_nonreplayable_hash, jtr_type: 'netntlm' }

          before(:example) do
            core.private = private
          end

          it 'should have the proper formatting with extant data'
          it 'should have the proper formatting with a missing public'
          it 'should have the proper formatting with a missing private'
        end
      end

      describe "v2" do
        describe "netlmv2" do
          let(:private){ FactoryBot.build :metasploit_credential_non_replayable_hash, jtr_type: 'netlmv2' }

          before(:example) do
            core.private = private
          end

          it 'should have the proper formatting with extant data'
          it 'should have the proper formatting with a missing public'
          it 'should have the proper formatting with a missing private'
        end

        describe "netntlmv2" do
          let(:private){ FactoryBot.build :metasploit_credential_non_replayable_hash, jtr_type: 'netntlmv2' }

          before(:example) do
            core.private = private
          end

          it 'should have the proper formatting with extant data'
          it 'should have the proper formatting with a missing public'
          it 'should have the proper formatting with a missing private'
        end
      end
    end
  end
end