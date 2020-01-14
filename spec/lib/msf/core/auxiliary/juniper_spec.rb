# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/auxiliary/juniper'

RSpec.describe Msf::Auxiliary::Juniper do
  class DummyJuniperClass
    include Msf::Auxiliary::Juniper
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
    def store_cred(hsh=nil)
      raise StandardError.new("This method needs to be stubbed.")
    end
    def fullname
      "auxiliary/scanner/snmp/juniper_dummy"
    end
    def myworkspace
      raise StandardError.new("This method needs to be stubbed.")
    end
  end

  subject(:aux_juniper) { DummyJuniperClass.new }

  let!(:workspace) { FactoryBot.create(:mdm_workspace) }

  context '#create_credential_and_login' do

    let(:session) { FactoryBot.create(:mdm_session) }

    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace)}

    let(:user) { FactoryBot.create(:mdm_user)}

    subject(:test_object) { DummyJuniperClass.new }

    let(:workspace) { FactoryBot.create(:mdm_workspace) }
    let(:service) { FactoryBot.create(:mdm_service, host: FactoryBot.create(:mdm_host, workspace: workspace)) }
    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace) }

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
        private_type: :nonreplayable_hash,
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

  context '#juniper_screenos_config_eater' do
    before(:example) do
      expect(aux_juniper).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'deals with admin credentials' do
      expect(aux_juniper).to receive(:print_good).with('Admin user netscreen found with password hash nKVUM2rwMUzPcrkG5sWIHdCtqkAibn')
      expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper ScreenOS'})
      expect(aux_juniper).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
          username: "netscreen",
          private_data: "nKVUM2rwMUzPcrkG5sWIHdCtqkAibn",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_juniper.juniper_screenos_config_eater('127.0.0.1',161,
        "set admin name \"netscreen\"\n" <<
        "set admin password \"nKVUM2rwMUzPcrkG5sWIHdCtqkAibn\"\n")
    end

    it 'deals with user account with password hash' do
      expect(aux_juniper).to receive(:print_good).with('User 1 named testuser found with password hash 02b0jt2gZGipCiIEgl4eainqZIKzjSNQYLIwE=. Enable permission: enable')
      expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper ScreenOS'})
      expect(aux_juniper).to receive(:store_loot).with("juniper.netscreen.config", "text/plain", "127.0.0.1",
          "set user \"testuser\" uid 1\n" <<
          "set user \"testuser\" type auth\n" <<
          "set user \"testuser\" hash-password \"02b0jt2gZGipCiIEgl4eainqZIKzjSNQYLIwE=\"\n" <<
          "set user \"testuser\" enable",
        "config.txt", "Juniper Netscreen Configuration"
      )
      expect(aux_juniper).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1337,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
          username: "testuser",
          jtr_format: "sha1",
          private_data: "02b0jt2gZGipCiIEgl4eainqZIKzjSNQYLIwE=",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )

      aux_juniper.juniper_screenos_config_eater('127.0.0.1',1337,
        "set user \"testuser\" uid 1\n" <<
        "set user \"testuser\" type auth\n" <<
        "set user \"testuser\" hash-password \"02b0jt2gZGipCiIEgl4eainqZIKzjSNQYLIwE=\"\n" <<
        "set user \"testuser\" enable\n")
    end

    context 'deals with snmp-server community' do

      it 'with Read permission' do
        expect(aux_juniper).to receive(:print_good).with('SNMP community sales with permissions Read-Only')
        expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper ScreenOS'})
        expect(aux_juniper).to receive(:create_credential_and_login).with(
          {
            address: "127.0.0.1",
            port: 161,
            protocol: "udp",
            workspace_id: workspace.id,
            origin_type: :service,
            service_name: 'snmp',
            module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
            private_data: "sales",
            private_type: :password,
            status: Metasploit::Model::Login::Status::UNTRIED,
            access_level: 'RO'
          }
        )
        aux_juniper.juniper_screenos_config_eater('127.0.0.1',1337,'set snmp community "sales" Read-Only Trap-on traffic version v1')
      end

      it 'with Read-Write permission' do
        expect(aux_juniper).to receive(:print_good).with('SNMP community sales with permissions Read-Write')
        expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper ScreenOS'})
        expect(aux_juniper).to receive(:create_credential_and_login).with(
          {
            address: "127.0.0.1",
            port: 161,
            protocol: "udp",
            workspace_id: workspace.id,
            origin_type: :service,
            service_name: 'snmp',
            module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
            private_data: "sales",
            private_type: :password,
            status: Metasploit::Model::Login::Status::UNTRIED,
            access_level: 'RW'
          }
        )
        aux_juniper.juniper_screenos_config_eater('127.0.0.1',1337,'set snmp community "sales" Read-Write Trap-on traffic version v1')
      end

    end

    it 'deals with ppp configurations' do
      expect(aux_juniper).to receive(:print_good).with('PPTP Profile ISP with username username hash fzSzAn31N4Sbh/sukoCDLvhJEdn0DVK7vA== via pap')
      expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper ScreenOS'})
      expect(aux_juniper).to receive(:store_loot).with(
        "juniper.netscreen.config", "text/plain", "127.0.0.1",
          "setppp profile \"ISP\" auth type pap\n" <<
          "setppp profile \"ISP\" auth local-name \"username\"\n" <<
          "setppp profile \"ISP\" auth secret \"fzSzAn31N4Sbh/sukoCDLvhJEdn0DVK7vA==\"",
        "config.txt", "Juniper Netscreen Configuration"
      )
      expect(aux_juniper).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1723,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'PPTP',
          module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
          username: "username",
          private_data: "fzSzAn31N4Sbh/sukoCDLvhJEdn0DVK7vA==",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_juniper.juniper_screenos_config_eater('127.0.0.1',1337,
        "setppp profile \"ISP\" auth type pap\n" <<
        "setppp profile \"ISP\" auth local-name \"username\"\n" <<
        "setppp profile \"ISP\" auth secret \"fzSzAn31N4Sbh/sukoCDLvhJEdn0DVK7vA==\"\n"
      )
    end

    it 'deals with ike configurations' do
      expect(aux_juniper).to receive(:print_good).with('IKE Profile To-Cisco to 2.2.2.1 with password netscreen via pre-g2-des-sha')
      expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper ScreenOS'})
      expect(aux_juniper).to receive(:store_loot).with(
        "juniper.netscreen.config", "text/plain", "127.0.0.1",
        "set ike gateway \"To-Cisco\" address 2.2.2.1 Main outgoing-interface \"ethernet1\" preshare \"netscreen\" proposal \"pre-g2-des-sha\"",
        "config.txt", "Juniper Netscreen Configuration"
      )
      expect(aux_juniper).to receive(:create_credential_and_login).with(
        {
          address: "2.2.2.1",
          port: 500,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'IKE',
          module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
          private_data: "netscreen",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_juniper.juniper_screenos_config_eater('127.0.0.1',1337,'set ike gateway "To-Cisco" address 2.2.2.1 Main outgoing-interface "ethernet1" preshare "netscreen" proposal "pre-g2-des-sha"')
    end

  end

  context '#juniper_junos_config_eater' do
    before(:example) do
      expect(aux_juniper).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'deals with root credentials' do
      expect(aux_juniper).to receive(:print_good).with('root password hash: $1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E.')
      expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
      #expect(aux_juniper).to receive(:store_loot).with(
      #  "juniper.netscreen.config", "text/plain", "127.0.0.1", "enable password 1511021F0725", "config.txt", "Cisco IOS Configuration"
      #)
      expect(aux_juniper).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
          username: "root",
          private_data: "$1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E.",
          jtr_format: "md5",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_juniper.juniper_junos_config_eater('127.0.0.1',161,
        %q(system {
             root-authentication {
               encrypted-password "$1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E."; ## SECRET-DATA
             }
           }
        )
      )
    end

    context 'deals with user account with password hash' do
      it 'with super-user' do
        expect(aux_juniper).to receive(:print_good).with('User 2000 named newuser in group super-user found with password hash $1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/.')
        expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
        expect(aux_juniper).to receive(:store_loot).with("juniper.junos.config", "text/plain", "127.0.0.1",
          "system {\n                 login {\n                     user newuser {\n                         uid 2000;\n                         class super-user;\n                         authentication {\n                             encrypted-password \"$1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/\"; ## SECRET-DATA\n                         }\n                     }\n                 }\n             }",
          "config.txt", "Juniper JunOS Configuration"
        )
        expect(aux_juniper).to receive(:create_credential_and_login).with(
          {
            address: "127.0.0.1",
            port: 1337,
            protocol: "tcp",
            workspace_id: workspace.id,
            origin_type: :service,
            service_name: '',
            module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
            username: "newuser",
            jtr_format: "md5",
            private_data: "$1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/",
            private_type: :nonreplayable_hash,
            status: Metasploit::Model::Login::Status::UNTRIED
          }
        )

        aux_juniper.juniper_junos_config_eater('127.0.0.1',1337,
          %q(system {
                 login {
                     user newuser {
                         uid 2000;
                         class super-user;
                         authentication {
                             encrypted-password "$1$rm8FaMFY$k4LFxqsVAiGO5tKqyO9jJ/"; ## SECRET-DATA
                         }
                     }
                 }
             }
          )
        )
      end

      it 'with operator' do
        expect(aux_juniper).to receive(:print_good).with('User 2002 named newuser2 in group operator found with password hash $1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0.')
        expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
        expect(aux_juniper).to receive(:store_loot).with("juniper.junos.config", "text/plain", "127.0.0.1",
          "system {\n                 login {\n                     user newuser2 {\n                         uid 2002;\n                         class operator;\n                         authentication {\n                             encrypted-password \"$1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0\"; ## SECRET-DATA\n                         }\n                     }\n                 }\n             }",
          "config.txt", "Juniper JunOS Configuration"
        )
        expect(aux_juniper).to receive(:create_credential_and_login).with(
          {
            address: "127.0.0.1",
            port: 1337,
            protocol: "tcp",
            workspace_id: workspace.id,
            origin_type: :service,
            service_name: '',
            module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
            username: "newuser2",
            jtr_format: "md5",
            private_data: "$1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0",
            private_type: :nonreplayable_hash,
            status: Metasploit::Model::Login::Status::UNTRIED
          }
        )

        aux_juniper.juniper_junos_config_eater('127.0.0.1',1337,
          %q(system {
                 login {
                     user newuser2 {
                         uid 2002;
                         class operator;
                         authentication {
                             encrypted-password "$1$aDZi44AP$bQGGjqPJ.F.Cm5QvX2yaa0"; ## SECRET-DATA
                         }
                     }
                 }
             }
          )
        )
      end

      it 'with read-only' do
        expect(aux_juniper).to receive(:print_good).with('User 2003 named newuser3 in group read-only found with password hash $1$1.YvKzUY$dcAj99KngGhFZTpxGjA93..')
        expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
        expect(aux_juniper).to receive(:store_loot).with("juniper.junos.config", "text/plain", "127.0.0.1",
          "system {\n                 login {\n                     user newuser3 {\n                         uid 2003;\n                         class read-only;\n                         authentication {\n                             encrypted-password \"$1$1.YvKzUY$dcAj99KngGhFZTpxGjA93.\"; ## SECRET-DATA\n                         }\n                     }\n                 }\n             }",
          "config.txt", "Juniper JunOS Configuration"
        )
        expect(aux_juniper).to receive(:create_credential_and_login).with(
          {
            address: "127.0.0.1",
            port: 1337,
            protocol: "tcp",
            workspace_id: workspace.id,
            origin_type: :service,
            service_name: '',
            module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
            username: "newuser3",
            jtr_format: "md5",
            private_data: "$1$1.YvKzUY$dcAj99KngGhFZTpxGjA93.",
            private_type: :nonreplayable_hash,
            status: Metasploit::Model::Login::Status::UNTRIED
          }
        )

        aux_juniper.juniper_junos_config_eater('127.0.0.1',1337,
          %q(system {
                 login {
                     user newuser3 {
                         uid 2003;
                         class read-only;
                         authentication {
                             encrypted-password "$1$1.YvKzUY$dcAj99KngGhFZTpxGjA93."; ## SECRET-DATA
                         }
                     }
                 }
             }
          )
        )
      end

      it 'with unauthorized' do
        expect(aux_juniper).to receive(:print_good).with('User 2004 named newuser4 in group unauthorized found with password hash $1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/.')
        expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
        expect(aux_juniper).to receive(:store_loot).with("juniper.junos.config", "text/plain", "127.0.0.1",
          "system {\n                 login {\n                     user newuser4 {\n                         uid 2004;\n                         class unauthorized;\n                         authentication {\n                             encrypted-password \"$1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/\"; ## SECRET-DATA\n                         }\n                     }\n                 }\n             }",
          "config.txt", "Juniper JunOS Configuration"
        )
        expect(aux_juniper).to receive(:create_credential_and_login).with(
          {
            address: "127.0.0.1",
            port: 1337,
            protocol: "tcp",
            workspace_id: workspace.id,
            origin_type: :service,
            service_name: '',
            module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
            username: "newuser4",
            jtr_format: "md5",
            private_data: "$1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/",
            private_type: :nonreplayable_hash,
            status: Metasploit::Model::Login::Status::UNTRIED
          }
        )

        aux_juniper.juniper_junos_config_eater('127.0.0.1',1337,
          %q(system {
                 login {
                     user newuser4 {
                         uid 2004;
                         class unauthorized;
                         authentication {
                             encrypted-password "$1$bdWYaqOE$z6oTSJS3p1R8CoNaos9Ce/"; ## SECRET-DATA
                         }
                     }
                 }
             }
          )
        )
      end

    end

    context 'deals with snmp-server community' do

      it 'with Read permissions' do
        expect(aux_juniper).to receive(:print_good).with('SNMP community read with permissions read-only')
        expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
        expect(aux_juniper).to receive(:create_credential_and_login).with(
          {
            address: "127.0.0.1",
            port: 161,
            protocol: "udp",
            workspace_id: workspace.id,
            origin_type: :service,
            service_name: 'snmp',
            module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
            private_data: "read",
            private_type: :password,
            status: Metasploit::Model::Login::Status::UNTRIED,
            access_level: 'RO'
          }
        )
        aux_juniper.juniper_junos_config_eater('127.0.0.1',1337,
          %q(snmp {
                 community read {
                     authorization read-only;
                 }
             }
          )
        )
      end

      it 'with Read-Write permissions and view' do
        expect(aux_juniper).to receive(:print_good).with('SNMP community write with permissions read-write')
        expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
        expect(aux_juniper).to receive(:create_credential_and_login).with(
          {
            address: "127.0.0.1",
            port: 161,
            protocol: "udp",
            workspace_id: workspace.id,
            origin_type: :service,
            service_name: 'snmp',
            module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
            private_data: "write",
            private_type: :password,
            status: Metasploit::Model::Login::Status::UNTRIED,
            access_level: 'RW'
          }
        )
        aux_juniper.juniper_junos_config_eater('127.0.0.1',1337,
          %q(snmp {
                 community write {
                     view jweb-view-all;
                     authorization read-write;
                 }
             }
          )
        )
      end

      it 'with a space in the community string' do
        expect(aux_juniper).to receive(:print_good).with('SNMP community hello there with permissions read-write')
        expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
        expect(aux_juniper).to receive(:create_credential_and_login).with(
          {
            address: "127.0.0.1",
            port: 161,
            protocol: "udp",
            workspace_id: workspace.id,
            origin_type: :service,
            service_name: 'snmp',
            module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
            private_data: "hello there",
            private_type: :password,
            status: Metasploit::Model::Login::Status::UNTRIED,
            access_level: 'RW'
          }
        )
        aux_juniper.juniper_junos_config_eater('127.0.0.1',1337,
          %q(snmp {
                 community "hello there" {
                     authorization read-write;
                 }
             }
          )
        )
      end


    end

    it 'deals with radius' do
      expect(aux_juniper).to receive(:print_good).with('radius server 1.1.1.1 password hash: $9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV')
      expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
      expect(aux_juniper).to receive(:store_loot).with("juniper.junos.config", "text/plain", "127.0.0.1",
        "access {\n              radius-server {\n                  1.1.1.1 secret \"$9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV\"; ## SECRET-DATA\n              }\n           }",
        "config.txt", "Juniper JunOS Configuration"
      )
      expect(aux_juniper).to receive(:create_credential_and_login).with(
        {
          address: "1.1.1.1",
          port: 1812,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'radius',
          module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
          private_data: "$9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_juniper.juniper_junos_config_eater('127.0.0.1',1337,
        %q(access {
              radius-server {
                  1.1.1.1 secret "$9$Y-4GikqfF39JGCu1Ileq.PQ6AB1hrlMBIyKvWdV"; ## SECRET-DATA
              }
           }
        )
      )
    end

    it 'deals with pap' do
      expect(aux_juniper).to receive(:print_good).with('PPTP username \'pap_username\' hash $9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR via PAP')
      expect(aux_juniper).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Juniper JunOS'})
      expect(aux_juniper).to receive(:store_loot).with("juniper.junos.config", "text/plain", "127.0.0.1",
        "interfaces {\n               pp0 {\n                   unit 0 {\n                       ppp-options {\n                           pap {\n                               local-name \"'pap_username'\";\n                               local-password \"$9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR\"; ## SECRET-DATA\n                           }\n                      }\n                  }\n               }\n           }",
        "config.txt", "Juniper JunOS Configuration"
      )
      #expect(aux_juniper).to receive(:store_loot).with(
      #  "cisco.ios.config", "text/plain", "127.0.0.1", "password 5 1511021F0725", "config.txt", "Cisco IOS Configuration"
      #)
      expect(aux_juniper).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1723,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'pptp',
          module_fullname: "auxiliary/scanner/snmp/juniper_dummy",
          private_data: "$9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR",
          username: "'pap_username'",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_juniper.juniper_junos_config_eater('127.0.0.1',1337,
        %q(interfaces {
               pp0 {
                   unit 0 {
                       ppp-options {
                           pap {
                               local-name "'pap_username'";
                               local-password "$9$he4revM87-dsevm5TQCAp0BErvLxd4JDNdkPfT/9BIR"; ## SECRET-DATA
                           }
                      }
                  }
               }
           }
       )
      )
    end

  end


end
