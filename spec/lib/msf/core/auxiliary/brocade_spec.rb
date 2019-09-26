# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/auxiliary/brocade'

RSpec.describe Msf::Auxiliary::Brocade do
  class DummyBrocadeClass
    include Msf::Auxiliary::Brocade
    def framework
      Msf::Simple::Framework.create(
          'ConfigDirectory' => Rails.root.join('spec', 'dummy', 'framework', 'config').to_s,
          # don't load any module paths so we can just load the module under test and save time
          'DeferModuleLoads' => true
      )
    end
    def active_db?
      true
    end
    def print_good(str=nil)
      raise StandardError.new("This method needs to be stubbed.")
    end
    def print_bad(str=nil)
      raise StandardError.new("This method needs to be stubbed.")
    end
    def store_cred(hsh=nil)
      raise StandardError.new("This method needs to be stubbed.")
    end
    def fullname
      "auxiliary/scanner/snmp/brocade_dummy"
    end
    def myworkspace
      raise StandardError.new("This method needs to be stubbed.")
    end
  end

  subject(:aux_brocade) { DummyBrocadeClass.new }

  let!(:workspace) { FactoryGirl.create(:mdm_workspace) }

  context '#create_credential_and_login' do

    let(:session) { FactoryGirl.create(:mdm_session) }

    let(:task) { FactoryGirl.create(:mdm_task, workspace: workspace)}

    let(:user) { FactoryGirl.create(:mdm_user)}

    subject(:test_object) { DummyBrocadeClass.new }

    let(:workspace) { FactoryGirl.create(:mdm_workspace) }
    let(:service) { FactoryGirl.create(:mdm_service, host: FactoryGirl.create(:mdm_host, workspace: workspace)) }
    let(:task) { FactoryGirl.create(:mdm_task, workspace: workspace) }

    let(:login_data) {
      {
        address: service.host.address,
        port: service.port,
        service_name: service.name,
        protocol: service.proto,
        workspace_id: workspace.id,
        origin_type: :service,
        module_fullname: 'auxiliary/scanner/smb/smb_login',
        realm_key: 'Active Directory Domain',
        realm_value: 'contosso',
        username: 'Username',
        private_data: 'password',
        private_type: :password,
        status: Metasploit::Model::Login::Status::UNTRIED
      }
    }

    it 'creates a Metasploit::Credential::Login' do
      expect{test_object.create_credential_and_login(login_data)}.to change{Metasploit::Credential::Login.count}.by(1)
    end
    it "associates the Metasploit::Credential::Core with a task if passed" do
      login = test_object.create_credential_and_login(login_data.merge(task_id: task.id))
      expect(login.tasks).to include(task)
    end
  end

  context '#brocade_config_eater' do
    before(:example) do
      expect(aux_brocade).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'deals with enable passwords' do
      expect(aux_brocade).to receive(:print_good).with('enable password hash $1$QP3H93Wm$uxYAs2HmAK01QiP3ig5tm.')
      expect(aux_brocade).to receive(:print_bad).with('password-display is disabled, no password hashes displayed in config')
      expect(aux_brocade).to receive(:store_loot).with(
        "brocade.config", "text/plain", "127.0.0.1", "enable super-user-password 8 $1$QP3H93Wm$uxYAs2HmAK01QiP3ig5tm.", "config.txt", "Brocade Configuration"
      )
      expect(aux_brocade).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/brocade_dummy",
          username: 'enable',
          private_data: "$1$QP3H93Wm$uxYAs2HmAK01QiP3ig5tm.",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_brocade.brocade_config_eater('127.0.0.1',161,'enable super-user-password 8 $1$QP3H93Wm$uxYAs2HmAK01QiP3ig5tm.')
    end

    it 'deals with user passwords' do
      expect(aux_brocade).to receive(:print_good).with('User brocade of type 8 found with password hash $1$YBaHUWpr$PzeUrP0XmVOyVNM5rYy99/.')
      expect(aux_brocade).to receive(:print_bad).with('password-display is disabled, no password hashes displayed in config')
      expect(aux_brocade).to receive(:store_loot).with(
        "brocade.config", "text/plain", "127.0.0.1", "username brocade password 8 $1$YBaHUWpr$PzeUrP0XmVOyVNM5rYy99/", "config.txt", "Brocade Configuration"
      )
      expect(aux_brocade).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/brocade_dummy",
          username: 'brocade',
          private_data: "$1$YBaHUWpr$PzeUrP0XmVOyVNM5rYy99/",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_brocade.brocade_config_eater('127.0.0.1',161,'username brocade password 8 $1$YBaHUWpr$PzeUrP0XmVOyVNM5rYy99/')
    end

    it 'deals with snmp communities' do
      expect(aux_brocade).to receive(:print_good).with('ENCRYPTED SNMP community $Si2^=d with permissions rw')
      expect(aux_brocade).to receive(:print_bad).with('password-display is disabled, no password hashes displayed in config')
      expect(aux_brocade).to receive(:store_loot).with(
        "brocade.config", "text/plain", "127.0.0.1", "snmp-server community 1 $Si2^=d rw", "config.txt", "Brocade Configuration"
      )
      expect(aux_brocade).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: "auxiliary/scanner/snmp/brocade_dummy",
          private_data: "$Si2^=d",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_brocade.brocade_config_eater('127.0.0.1',161,'snmp-server community 1 $Si2^=d rw')
    end
    it 'deals with enable hidden passwords' do
      expect(aux_brocade).to receive(:print_bad).with('password-display is disabled, no password hashes displayed in config')
      expect(aux_brocade).to receive(:store_loot).with(
        "brocade.config", "text/plain", "127.0.0.1", "enable super-user-password 8 .....", "config.txt", "Brocade Configuration"
      )
      aux_brocade.brocade_config_eater('127.0.0.1',161,'enable super-user-password 8 .....')
    end

    it 'deals with user hidden passwords' do
      expect(aux_brocade).to receive(:print_bad).with('password-display is disabled, no password hashes displayed in config')
      expect(aux_brocade).to receive(:store_loot).with(
        "brocade.config", "text/plain", "127.0.0.1", "username brocade password 8 .....", "config.txt", "Brocade Configuration"
      )
      aux_brocade.brocade_config_eater('127.0.0.1',161,'username brocade password 8 .....')
    end

    it 'deals with snmp communities' do
      expect(aux_brocade).to receive(:print_bad).with('password-display is disabled, no password hashes displayed in config')
      expect(aux_brocade).to receive(:store_loot).with(
        "brocade.config", "text/plain", "127.0.0.1", "snmp-server community 1 ..... rw", "config.txt", "Brocade Configuration"
      )
      aux_brocade.brocade_config_eater('127.0.0.1',161,'snmp-server community 1 ..... rw')
    end
  end

end
