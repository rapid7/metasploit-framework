# frozen_string_literal: true
require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/command_dispatcher/creds'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Creds do

  if ENV['REMOTE_DB']
    before {skip("Awaiting credentials port")}
  end

  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:creds) do
    described_class.new(driver)
  end

  it { is_expected.to respond_to :active? }
  it { is_expected.to respond_to :creds_add }
  it { is_expected.to respond_to :creds_search }

  describe '#cmd_creds' do
    let(:username)            { 'thisuser' }
    let(:password)            { 'thispass' }
    let(:realm)               { 'thisrealm' }
    let(:realm_type)          { 'Active Directory Domain' }
    context 'Searching' do
      describe '-u' do
        let(:nomatch_username)    { 'thatuser' }
        let(:nomatch_password)    { 'thatpass' }
        let(:blank_username)      { '' }
        let(:blank_password)      { '' }
        let(:nonblank_username)   { 'nonblank_user' }
        let(:nonblank_password)   { 'nonblank_pass' }

        let!(:origin) { FactoryBot.create(:metasploit_credential_origin_import) }
        
        let!(:priv) { FactoryBot.create(:metasploit_credential_password, data: password) }
        let!(:pub) { FactoryBot.create(:metasploit_credential_username, username: username) }
        let!(:blank_pub) { blank_pub = FactoryBot.create(:metasploit_credential_blank_username) }
        let!(:nonblank_priv) { FactoryBot.create(:metasploit_credential_password, data: nonblank_password) }
        let!(:nonblank_pub) { FactoryBot.create(:metasploit_credential_username, username: nonblank_username) }
        let!(:blank_priv) { FactoryBot.create(:metasploit_credential_password, data: blank_password) }
        before(:example) do
          FactoryBot.create(:metasploit_credential_core,
            origin: origin,
            private: priv,
            public: pub,
            realm: nil,
            workspace: framework.db.workspace)
          
          FactoryBot.create(:metasploit_credential_core,
            origin: origin,
            private: nonblank_priv,
            public: blank_pub,
            realm: nil,
            workspace: framework.db.workspace)
            
          FactoryBot.create(:metasploit_credential_core,
            origin: origin,
            private: blank_priv,
            public: nonblank_pub,
            realm: nil,
            workspace: framework.db.workspace)
        end

        context 'when the credential is present' do
          it 'should show a user that matches the given expression' do
            creds.cmd_creds('-u', username)
            expect(@output).to eq([
              'Credentials',
              '===========',
              '',
              'host  origin  service  public    private   realm  private_type  JtR Format',
              '----  ------  -------  ------    -------   -----  ------------  ----------',
              '                       thisuser  thispass         Password      '
            ])
          end

          it 'should match a regular expression' do
            creds.cmd_creds('-u', "^#{username}$")
            expect(@output).to eq([
              'Credentials',
              '===========',
              '',
              'host  origin  service  public    private   realm  private_type  JtR Format',
              '----  ------  -------  ------    -------   -----  ------------  ----------',
              '                       thisuser  thispass         Password      '
            ])
          end

          it 'should return nothing for a non-matching regular expression' do
            creds.cmd_creds('-u', "^#{nomatch_username}$")
            expect(@output).to eq([
              'Credentials',
              '===========',
              '',
              'host  origin  service  public  private  realm  private_type  JtR Format',
              '----  ------  -------  ------  -------  -----  ------------  ----------'
            ])
          end

          context 'and when the username is blank' do
            it 'should show a user that matches the given expression' do
              creds.cmd_creds('-u', blank_username)
              expect(@output).to eq([
                'Credentials',
                '===========',
                '',
                'host  origin  service  public  private        realm  private_type  JtR Format',
                '----  ------  -------  ------  -------        -----  ------------  ----------',
                '                               nonblank_pass         Password      '
              ])
            end
          end
          context 'and when the password is blank' do
            it 'should show a user that matches the given expression' do
              creds.cmd_creds('-P', blank_password)
              expect(@output).to eq([
                'Credentials',
                '===========',
                '',
                'host  origin  service  public         private  realm  private_type  JtR Format',
                '----  ------  -------  ------         -------  -----  ------------  ----------',
                '                       nonblank_user                  Password      '
              ])
            end
          end
        end

        context 'when the credential is absent' do
          context 'due to a nonmatching username' do
            it 'should return a blank set' do
              creds.cmd_creds('-u', nomatch_username)
              expect(@output).to eq([
                'Credentials',
                '===========',
                '',
                'host  origin  service  public  private  realm  private_type  JtR Format',
                '----  ------  -------  ------  -------  -----  ------------  ----------'
              ])
            end
          end
          context 'due to a nonmatching password' do
            it 'should return a blank set' do
              creds.cmd_creds('-P', nomatch_password)
              expect(@output).to eq([
                'Credentials',
                '===========',
                '',
                'host  origin  service  public  private  realm  private_type  JtR Format',
                '----  ------  -------  ------  -------  -----  ------------  ----------'
              ])
            end
          end
        end
      end

      describe '-t' do
        context 'with an invalid type' do
          it 'should print the list of valid types' do
            creds.cmd_creds('-t', 'asdf')
            expect(@error).to match_array [
              'Unrecognized credential type asdf -- must be one of password,ntlm,hash'
            ]
          end
        end

        context 'with valid types' do
          let(:ntlm_hash) { '1443d06412d8c0e6e72c57ef50f76a05:27c433245e4763d074d30a05aae0af2c' }

          let!(:pub) do
            FactoryBot.create(:metasploit_credential_username, username: username)
          end
          let!(:password_core) do
            priv = FactoryBot.create(:metasploit_credential_password, data: password)
            FactoryBot.create(:metasploit_credential_core,
                               origin: FactoryBot.create(:metasploit_credential_origin_import),
                               private: priv,
                               public: pub,
                               realm: nil,
                               workspace: framework.db.workspace)
          end

          #         # Somehow this is hitting a unique constraint on Cores with the same
          #         # Public, even though it has a different Private. Skip for now
          #         let!(:ntlm_core) do
          #           priv = FactoryBot.create(:metasploit_credential_ntlm_hash, data: ntlm_hash)
          #           FactoryBot.create(:metasploit_credential_core,
          #                              origin: FactoryBot.create(:metasploit_credential_origin_import),
          #                              private: priv,
          #                              public: pub,
          #                              realm: nil,
          #                              workspace: framework.db.workspace)
          #         end
          #         let!(:nonreplayable_core) do
          #           priv = FactoryBot.create(:metasploit_credential_nonreplayable_hash, data: 'asdf')
          #           FactoryBot.create(:metasploit_credential_core,
          #                              origin: FactoryBot.create(:metasploit_credential_origin_import),
          #                              private: priv,
          #                              public: pub,
          #                              realm: nil,
          #                              workspace: framework.db.workspace)
          #         end

          after(:example) do
            # ntlm_core.destroy
            password_core.destroy
            # nonreplayable_core.destroy
          end

          context 'password' do
            it 'should show just the password' do
              creds.cmd_creds('-t', 'password')
              # Table matching really sucks
              expect(@output).to eq([
                'Credentials',
                '===========',
                '',
                'host  origin  service  public    private   realm  private_type  JtR Format',
                '----  ------  -------  ------    -------   -----  ------------  ----------',
                '                       thisuser  thispass         Password      '
              ])
            end
          end

          context 'ntlm' do
            it 'should show just the ntlm' do
              skip 'Weird uniqueness constraint on Core (workspace_id, public_id)'

              creds.cmd_creds('-t', 'ntlm')
              # Table matching really sucks
              expect(@output).to =~ [
                'Credentials',
                '===========',
                '',
                'host  service  public    private                                                            realm  private_type  JtR Format',
                '----  -------  ------    -------                                                            -----  ------------  ----------',
                "               thisuser  #{ntlm_hash}         NTLM hash"
              ]
            end
          end
        end
      end
    end
    describe 'Adding' do
      let(:pub) { FactoryBot.create(:metasploit_credential_username, username: username) }
      let(:priv) { FactoryBot.create(:metasploit_credential_password, data: password) }
      let(:r) { FactoryBot.create(:metasploit_credential_realm, key: realm_type, value: realm) }
      context 'Cores with public privates and realms' do
        context 'username password and realm' do
          it 'creates a core if one does not exist' do
            expect {
              creds.cmd_creds('add', "user:#{username}", "password:#{password}", "realm:#{realm}")
            }.to change { Metasploit::Credential::Core.count }.by 1
          end
          it 'does not create a core if it already exists' do
            FactoryBot.create(:metasploit_credential_core,
              origin: FactoryBot.create(:metasploit_credential_origin_import),
              private: priv,
              public: pub,
              realm: r,
              workspace: framework.db.workspace)
              expect {
                creds.cmd_creds('add', "user:#{username}", "password:#{password}", "realm:#{realm}")
              }.to_not change { Metasploit::Credential::Core.count }
            end
          end
          context 'username and realm' do
            it 'creates a core if one does not exist' do
              expect {
                creds.cmd_creds('add', "user:#{username}", "realm:#{realm}")
              }.to change { Metasploit::Credential::Core.count }.by 1
            end
            it 'does not create a core if it already exists' do
              FactoryBot.create(:metasploit_credential_core,
                origin: FactoryBot.create(:metasploit_credential_origin_import),
                private: nil,
                public: pub,
                realm: r,
                workspace: framework.db.workspace)
              expect {
                creds.cmd_creds('add', "user:#{username}", "realm:#{realm}")
              }.to_not change { Metasploit::Credential::Core.count }
            end
          end

          context 'username and password' do
            it 'creates a core if one does not exist' do
              expect {
                creds.cmd_creds('add', "user:#{username}", "password:#{password}")
              }.to change { Metasploit::Credential::Core.count }.by 1
            end
            it 'does not create a core if it already exists' do
              FactoryBot.create(:metasploit_credential_core,
                origin: FactoryBot.create(:metasploit_credential_origin_import),
                private: priv,
                public: pub,
                realm: nil,
                workspace: framework.db.workspace)
              expect {
                creds.cmd_creds('add', "user:#{username}", "password:#{password}")
              }.to_not change { Metasploit::Credential::Core.count }
            end
          end

          context 'password and realm' do
            it 'creates a core if one does not exist' do
              expect {
                creds.cmd_creds('add', "password:#{password}", "realm:#{realm}")
              }.to change { Metasploit::Credential::Core.count }.by 1
            end
            it 'does not create a core if it already exists' do
              FactoryBot.create(:metasploit_credential_core,
                origin: FactoryBot.create(:metasploit_credential_origin_import),
                private: priv,
                public: nil,
                realm: r,
                workspace: framework.db.workspace)
              expect {
                creds.cmd_creds('add', "password:#{password}", "realm:#{realm}")
              }.to_not change { Metasploit::Credential::Core.count }
            end
          end

          context 'username' do
            it 'creates a core if one does not exist' do
              expect {
                creds.cmd_creds('add', "user:#{username}")
              }.to change { Metasploit::Credential::Core.count }.by 1
            end
            it 'does not create a core if it already exists' do
              FactoryBot.create(:metasploit_credential_core,
                origin: FactoryBot.create(:metasploit_credential_origin_import),
                private: nil,
                public: pub,
                realm: nil,
                workspace: framework.db.workspace)
              expect {
                creds.cmd_creds('add', "user:#{username}")
              }.to_not change { Metasploit::Credential::Core.count }
            end
          end
        context 'private_types' do
          context 'password' do
            it 'creates a core if one does not exist' do
              expect {
                creds.cmd_creds('add', "password:#{password}")
              }.to change { Metasploit::Credential::Core.count }.by 1
            end
            it 'does not create a core if it already exists' do
              FactoryBot.create(:metasploit_credential_core,
                origin: FactoryBot.create(:metasploit_credential_origin_import),
                private: priv,
                public: nil,
                realm: nil,
                workspace: framework.db.workspace)
              expect {
                creds.cmd_creds('add', "password:#{password}")
              }.to_not change { Metasploit::Credential::Core.count }
            end
          end
          context 'ntlm' do
            let(:priv) { FactoryBot.create(:metasploit_credential_ntlm_hash) }
            it 'creates a core if one does not exist' do
              expect {
                creds.cmd_creds('add', "ntlm:#{priv.data}")
              }.to change { Metasploit::Credential::Core.count }.by 1
            end
            it 'does not create a core if it already exists' do
              FactoryBot.create(:metasploit_credential_core,
                origin: FactoryBot.create(:metasploit_credential_origin_import),
                private: priv,
                public: nil,
                realm: nil,
                workspace: framework.db.workspace)
              expect {
                creds.cmd_creds('add', "ntlm:#{priv.data}")
              }.to_not change { Metasploit::Credential::Core.count }
            end
          end
          context 'hash' do
            let(:priv) { FactoryBot.create(:metasploit_credential_nonreplayable_hash) }
            it 'creates a core if one does not exist' do
              expect {
                creds.cmd_creds('add', "hash:#{priv.data}")
              }.to change { Metasploit::Credential::Core.count }.by 1
            end
            it 'does not create a core if it already exists' do
              FactoryBot.create(:metasploit_credential_core,
                origin: FactoryBot.create(:metasploit_credential_origin_import),
                private: priv,
                public: nil,
                realm: nil,
                workspace: framework.db.workspace)
              expect {
                creds.cmd_creds('add', "hash:#{priv.data}")
              }.to_not change { Metasploit::Credential::Core.count }
            end
          end
          context 'ssh-key' do
            let(:priv) { FactoryBot.create(:metasploit_credential_ssh_key) }
            before(:each) do
              @file = Tempfile.new('id_rsa')
              @file.write(priv.data)
              @file.close
            end
            it 'creates a core if one does not exist' do
              expect {
                creds.cmd_creds('add', "user:#{username}", "ssh-key:#{@file.path}")
              }.to change { Metasploit::Credential::Core.count }.by 1
            end
            it 'does not create a core if it already exists' do
              FactoryBot.create(:metasploit_credential_core,
                origin: FactoryBot.create(:metasploit_credential_origin_import),
                private: priv,
                public: pub,
                realm: nil,
                workspace: framework.db.workspace)
              expect {
                creds.cmd_creds('add', "user:#{username}", "ssh-key:#{@file.path}")
              }.to_not change { Metasploit::Credential::Core.count }
            end
          end
        end
        context 'realm-types' do
          Metasploit::Model::Realm::Key::SHORT_NAMES.each do |short_name, long_name|
            context "#{short_name}" do
              let(:r) { FactoryBot.create(:metasploit_credential_realm, key: long_name) }
              it 'creates a core if one does not exist' do
                expect {
                  creds.cmd_creds('add', "realm:#{r.value}", "realm-type:#{short_name}")
                }.to change { Metasploit::Credential::Core.count }.by 1
              end
              it 'does not create a core if it already exists' do
                FactoryBot.create(:metasploit_credential_core,
                  origin: FactoryBot.create(:metasploit_credential_origin_import),
                  private: nil,
                  public: nil,
                  realm: r,
                  workspace: framework.db.workspace)
                expect {
                  creds.cmd_creds('add', "realm:#{r.value}", "realm-type:#{short_name}")
                }.to_not change { Metasploit::Credential::Core.count }
              end
            end
          end
        end
      end
      context 'Cores with Logins' do
        let(:address) { '192.168.0.1' }
        let(:port)    { 80 }
        let(:proto)   { 'tcp' }
        let(:name)    { 'Web Service' }
        context 'With valid params' do
          let(:create_core_with_login) {
            creds.cmd_creds(
              'add', "user:#{username}", "password:#{password}", "realm:#{realm}",
              "address:#{address}", "port:#{port}", "protocol:#{proto}", "service-name:#{name}")
          }
          it 'creates a core' do
            expect { create_core_with_login }.to change { Metasploit::Credential::Core.count }.by 1
          end
          it 'creates a login' do
            expect { create_core_with_login }.to change { Metasploit::Credential::Login.count }.by 1
          end
          it 'creates a service' do
            expect { create_core_with_login }.to change { Mdm::Service.count }.by 1
          end
          it 'creates a host' do
            expect { create_core_with_login }.to change { Mdm::Host.count }.by 1
          end
        end


      end
    end
  end
end
