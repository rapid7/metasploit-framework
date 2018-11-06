require 'spec_helper'
require 'tempfile'

RSpec.describe Metasploit::Credential::Migrator do


  let(:workspace){ FactoryBot.create(:mdm_workspace) }
  let(:host){ FactoryBot.create(:mdm_host, workspace: workspace)}
  let(:service){ FactoryBot.create(:mdm_service, host: host)}


  subject(:migrator){ Metasploit::Credential::Migrator.new(workspace) }

  describe "#convert_creds_in_workspace" do
    describe "when there are no Mdm::Cred objects in the workspace" do
      before(:example) do
        workspace.services.each do |service|
          service.creds = []
        end
      end

      it 'should not change the Core count' do
        expect{migrator.convert_creds_in_workspace(workspace)}.to_not change(Metasploit::Credential::Core, :count)
      end

      it 'should not change the Login count' do
        expect{migrator.convert_creds_in_workspace(workspace)}.to_not change(Metasploit::Credential::Login, :count)
      end

      it 'should not change the Private count' do
        expect{migrator.convert_creds_in_workspace(workspace)}.to_not change(Metasploit::Credential::Private, :count)
      end

      it 'should not change the Public count' do
        expect{migrator.convert_creds_in_workspace(workspace)}.to_not change(Metasploit::Credential::Public, :count)
      end
    end

    describe "when there are Mdm::Cred objects present in the workspace" do

      let(:host1){ FactoryBot.create(:mdm_host, workspace: workspace)}
      let(:host2){ FactoryBot.create(:mdm_host, workspace: workspace)}
      let(:host3){ FactoryBot.create(:mdm_host, workspace: workspace)}

      let(:service1){ FactoryBot.create(:mdm_service, host: host1)}
      let(:service2){ FactoryBot.create(:mdm_service, host: host2)}
      let(:service3){ FactoryBot.create(:mdm_service, host: host3)}

      let!(:cred1){ FactoryBot.create(:mdm_cred, service: service1)}
      let!(:cred2){ FactoryBot.create(:mdm_cred, service: service2)}
      let!(:cred3){ FactoryBot.create(:mdm_cred, service: service3)}

      it 'should migrate them into Metasploit::Credential::Core objects' do
        expect{migrator.convert_creds_in_workspace(workspace)}.to change(Metasploit::Credential::Core, :count).from(0).to(3)
      end

      describe "new Publics" do
        before(:example) do
          migrator.convert_creds_in_workspace(workspace)
        end

        it "should be created for each Mdm::Cred" do
          expect(Metasploit::Credential::Public.pluck(:username)).to match_array([cred1.user, cred2.user, cred3.user])
        end
      end

      describe "new Privates" do
        before(:example) do
          migrator.convert_creds_in_workspace(workspace)
        end

        it "should be created for each Mdm::Cred" do
          expect(Metasploit::Credential::Password.pluck(:data)).to match_array([cred1.pass, cred2.pass, cred3.pass])
        end
      end
    end

    describe "creating the proper kinds of Private objects" do
      describe "when an Mdm::Cred is an SMB hash" do
        let(:cred) do
          FactoryBot.create(:mdm_cred,
                             service: service,
                             ptype: 'smb_hash',
                             pass: FactoryBot.build(:metasploit_credential_ntlm_hash, password_data: 'f00b4rawesomesauc3!').data
          )
        end

        before(:example) do
          migrator.convert_creds_in_workspace(cred.service.host.workspace)
        end

        it 'should create a new NTLMHash in the database' do
          expect(Metasploit::Credential::NTLMHash.where(data: cred.pass)).not_to be_blank
        end
      end

      describe "when an Mdm::Cred is an SSH key" do
        let(:ssh_key_content){ FactoryBot.build(:metasploit_credential_ssh_key).data }

        context "when Cred#pass points to a file system path" do

          let(:path_to_ssh_key) do
            t = Tempfile.new('ssh')
            t.write(ssh_key_content)
            t.close
            t.path
          end

          let(:cred) do
            FactoryBot.create(:mdm_cred,
                             service: service,
                             ptype: 'ssh_key',
                             pass: path_to_ssh_key
            )
          end

          before(:example) do
            migrator.convert_creds_in_workspace(cred.service.host.workspace)
          end

          it 'should create a new SSHKey in the database' do
            expect(Metasploit::Credential::SSHKey.where(data: ssh_key_content)).not_to be_blank
          end
        end

        context "when Cred#pass just straight up contains the private key" do
          let(:cred) do
            FactoryBot.create(:mdm_cred,
                               service: service,
                               ptype: 'ssh_key',
                               pass: ssh_key_content
            )
          end

          before(:example) do
            migrator.convert_creds_in_workspace(cred.service.host.workspace)
          end

          it 'should create a new SSHKey in the database' do
            expect(Metasploit::Credential::SSHKey.where(data: ssh_key_content)).not_to be_blank
          end
        end

        context "when Cred#pass is just total garbage" do
          let(:cred) do
            FactoryBot.create(:mdm_cred,
                               service: service,
                               ptype: 'ssh_key',
                               pass: '#YOLOSWAG'
            )
          end

          before(:example) do
            migrator.convert_creds_in_workspace(cred.service.host.workspace)
          end

          it 'should not create a new SSHKey in the database' do
            expect(Metasploit::Credential::SSHKey.count).to be_zero
          end
        end

      end

      describe "when an Mdm::Cred is a password" do
        let(:cred) do
          FactoryBot.create(:mdm_cred,
                             service: service,
                             ptype: 'password',
                             pass: FactoryBot.build(:metasploit_credential_password, data: 'f00b4rawesomesauc3!').data
          )
        end

        before(:example) do
          migrator.convert_creds_in_workspace(cred.service.host.workspace)
        end

        it 'should create a new Password in the database' do
          expect(Metasploit::Credential::Password.where(data: cred.pass)).not_to be_blank
        end
      end

      describe "when an Mdm::Cred is another kind of hash" do
        let(:cred) do
          FactoryBot.create(:mdm_cred,
                             service: service,
                             ptype: 'salted_sha1_hash',
                             pass: FactoryBot.build(:metasploit_credential_nonreplayable_hash, password_data: 'f00b4rawesomesauc3!').data
          )
        end

        before(:example) do
          migrator.convert_creds_in_workspace(cred.service.host.workspace)
        end

        it 'should create a new NonreplayableHash in the database' do
          expect(Metasploit::Credential::NonreplayableHash.where(data: cred.pass)).not_to be_blank
        end
      end
    end



  end

end
