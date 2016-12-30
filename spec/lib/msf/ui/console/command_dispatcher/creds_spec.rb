require 'spec_helper'

require 'msf/ui'
require 'msf/ui/console/command_dispatcher/creds'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Creds do
  include_context 'Msf::DBManager'
  include_context 'Msf::UIDriver'

  subject(:creds) do
    described_class.new(driver)
  end

  it { is_expected.to respond_to :active? }
  it { is_expected.to respond_to :creds_add }
  it { is_expected.to respond_to :creds_search }
  
  describe "#cmd_creds" do
    let(:username)            { "thisuser" }
    let(:password)            { "thispass" }

    describe "-u" do
      let(:nomatch_username)    { "thatuser" }
      let(:nomatch_password)    { "thatpass" }
      let(:blank_username)      { "" }
      let(:blank_password)      { "" }
      let(:nonblank_username)   { "nonblank_user" }
      let(:nonblank_password)   { "nonblank_pass" }

      let!(:origin) { FactoryGirl.create(:metasploit_credential_origin_import) }

      before(:example) do
        priv = FactoryGirl.create(:metasploit_credential_password, data: password)
        pub = FactoryGirl.create(:metasploit_credential_username, username: username)
        FactoryGirl.create(:metasploit_credential_core,
                           origin: origin,
                           private: priv,
                           public: pub,
                           realm: nil,
                           workspace: framework.db.workspace)
        blank_pub = FactoryGirl.create(:metasploit_credential_blank_username)
        nonblank_priv = FactoryGirl.create(:metasploit_credential_password, data: nonblank_password)
        FactoryGirl.create(:metasploit_credential_core,
                           origin: origin,
                           private: nonblank_priv,
                           public: blank_pub,
                           realm: nil,
                           workspace: framework.db.workspace)
        nonblank_pub = FactoryGirl.create(:metasploit_credential_username, username: nonblank_username)
        blank_priv = FactoryGirl.create(:metasploit_credential_password, data: blank_password)
        FactoryGirl.create(:metasploit_credential_core,
                           origin: origin,
                           private: blank_priv,
                           public: nonblank_pub,
                           realm: nil,
                           workspace: framework.db.workspace)
      end

      context "when the credential is present" do
        it "should show a user that matches the given expression" do
          creds.cmd_creds("-u", username)
          expect(@output).to eq([
            "Credentials",
            "===========",
            "",
            "host  origin  service  public    private   realm  private_type",
            "----  ------  -------  ------    -------   -----  ------------",
            "                       thisuser  thispass         Password"
          ])
        end

        it 'should match a regular expression' do
          creds.cmd_creds("-u", "^#{username}$")
          expect(@output).to eq([
            "Credentials",
            "===========",
            "",
            "host  origin  service  public    private   realm  private_type",
            "----  ------  -------  ------    -------   -----  ------------",
            "                       thisuser  thispass         Password"
          ])
        end

        it 'should return nothing for a non-matching regular expression' do
          creds.cmd_creds("-u", "^#{nomatch_username}$")
          expect(@output).to eq([
            "Credentials",
            "===========",
            "",
            "host  origin  service  public  private  realm  private_type",
            "----  ------  -------  ------  -------  -----  ------------"
          ])
        end

        context "and when the username is blank" do
          it "should show a user that matches the given expression" do
            creds.cmd_creds("-u", blank_username)
            expect(@output).to eq([
              "Credentials",
              "===========",
              "",
              "host  origin  service  public  private        realm  private_type",
              "----  ------  -------  ------  -------        -----  ------------",
              "                               nonblank_pass         Password"
            ])
          end
        end
        context "and when the password is blank" do
          it "should show a user that matches the given expression" do
            creds.cmd_creds("-P", blank_password)
            expect(@output).to eq([
              "Credentials",
              "===========",
              "",
              "host  origin  service  public         private  realm  private_type",
              "----  ------  -------  ------         -------  -----  ------------",
              "                       nonblank_user                  Password"
            ])
          end
        end
      end

      context "when the credential is absent" do
        context "due to a nonmatching username" do
          it "should return a blank set" do
            creds.cmd_creds("-u", nomatch_username)
            expect(@output).to eq([
              "Credentials",
              "===========",
              "",
              "host  origin  service  public  private  realm  private_type",
              "----  ------  -------  ------  -------  -----  ------------"
            ])
          end
        end
        context "due to a nonmatching password" do
          it "should return a blank set" do
            creds.cmd_creds("-P", nomatch_password)
            expect(@output).to eq([
              "Credentials",
              "===========",
              "",
              "host  origin  service  public  private  realm  private_type",
              "----  ------  -------  ------  -------  -----  ------------"
            ])
          end
        end
      end
    end

    describe "-t" do
      context "with an invalid type" do
        it "should print the list of valid types" do
          creds.cmd_creds("-t", "asdf")
          expect(@error).to match_array [
            "Unrecognized credential type asdf -- must be one of password,ntlm,hash"
          ]
        end
      end

      context "with valid types" do
        let(:ntlm_hash) { "1443d06412d8c0e6e72c57ef50f76a05:27c433245e4763d074d30a05aae0af2c" }

        let!(:pub) do
          FactoryGirl.create(:metasploit_credential_username, username: username)
        end
        let!(:password_core) do
          priv = FactoryGirl.create(:metasploit_credential_password, data: password)
          FactoryGirl.create(:metasploit_credential_core,
                             origin: FactoryGirl.create(:metasploit_credential_origin_import),
                             private: priv,
                             public: pub,
                             realm: nil,
                             workspace: framework.db.workspace)
        end

=begin
        # Somehow this is hitting a unique constraint on Cores with the same
        # Public, even though it has a different Private. Skip for now
        let!(:ntlm_core) do
          priv = FactoryGirl.create(:metasploit_credential_ntlm_hash, data: ntlm_hash)
          FactoryGirl.create(:metasploit_credential_core,
                             origin: FactoryGirl.create(:metasploit_credential_origin_import),
                             private: priv,
                             public: pub,
                             realm: nil,
                             workspace: framework.db.workspace)
        end
        let!(:nonreplayable_core) do
          priv = FactoryGirl.create(:metasploit_credential_nonreplayable_hash, data: 'asdf')
          FactoryGirl.create(:metasploit_credential_core,
                             origin: FactoryGirl.create(:metasploit_credential_origin_import),
                             private: priv,
                             public: pub,
                             realm: nil,
                             workspace: framework.db.workspace)
        end
=end

        after(:example) do
          #ntlm_core.destroy
          password_core.destroy
          #nonreplayable_core.destroy
        end

        context "password" do
          it "should show just the password" do
            creds.cmd_creds("-t", "password")
            # Table matching really sucks
            expect(@output).to eq([
              "Credentials",
              "===========",
              "",
              "host  origin  service  public    private   realm  private_type",
              "----  ------  -------  ------    -------   -----  ------------",
              "                       thisuser  thispass         Password"
            ])
          end
        end

        context "ntlm" do
          it "should show just the ntlm" do
            skip "Weird uniqueness constraint on Core (workspace_id, public_id)"

            creds.cmd_creds("-t", "ntlm")
            # Table matching really sucks
            expect(@output).to =~ [
              "Credentials",
              "===========",
              "",
              "host  service  public    private                                                            realm  private_type",
              "----  -------  ------    -------                                                            -----  ------------",
              "               thisuser  #{ntlm_hash                                                     }         NTLM hash"
            ]
          end
        end

      end
    end

    describe "add" do
      context "when no core exists" do
        it "should add a Core" do
          expect {
            creds.cmd_creds("add", "user:#{username}", "password:#{password}")
          }.to change{ Metasploit::Credential::Core.count }.by 1
        end
      end
      context "when a core already exists" do
        before(:example) do
          priv = FactoryGirl.create(:metasploit_credential_password, data: password)
          pub = FactoryGirl.create(:metasploit_credential_username, username: username)
          FactoryGirl.create(:metasploit_credential_core,
                             origin: FactoryGirl.create(:metasploit_credential_origin_import),
                             private: priv,
                             public: pub,
                             realm: nil,
                             workspace: framework.db.workspace)
        end
        it "should not add a Core" do
          expect {
            creds.cmd_creds("add", "user:#{username}", "password:#{password}")
          }.to_not change{ Metasploit::Credential::Core.count }
        end
      end
    end

  end

end
