# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/auxiliary/mikrotik'

RSpec.describe Msf::Auxiliary::Mikrotik do
  class DummyMikrotikClass
    include Msf::Auxiliary::Mikrotik
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
    def print_status(str=nil)
      raise StandardError.new("This method needs to be stubbed.")
    end
    def store_cred(hsh=nil)
      raise StandardError.new("This method needs to be stubbed.")
    end
    def fullname
      "auxiliary/scanner/snmp/mikrotik_dummy"
    end
    def myworkspace
      raise StandardError.new("This method needs to be stubbed.")
    end
  end

  subject(:aux_mikrotik) { DummyMikrotikClass.new }

  let!(:workspace) { FactoryBot.create(:mdm_workspace) }

  context '#create_credential_and_login' do

    let(:session) { FactoryBot.create(:mdm_session) }

    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace)}

    let(:user) { FactoryBot.create(:mdm_user)}

    subject(:test_object) { DummyMikrotikClass.new }
    
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

  context 'converts export to hash' do
    it 'handles nil' do
      result = aux_mikrotik.export_to_hash(nil)
      expect(result).to eq({})
    end

    it 'handles empty string' do
      result = aux_mikrotik.export_to_hash('')
      expect(result).to eq({})
    end

    it 'correctly with several values' do
      data = "# jul/17/2020 14:12:53 by RouterOS 6.45.9\n"
      data << "# software id = \n"
      data << "#\n"
      data << "#\n"
      data << "#\n"
      data << "/interface pppoe-client\n"
      data << "# Client is on slave interface\n"
      data << "add disabled=no interface=ether2 name=pppoe-user password=password service-name=internet user=user\n"
      data << "/system identity\n"
      data << "set name=mikrotik_hostname\n"
      result = aux_mikrotik.export_to_hash(data)
      expect(result).to eq(
        {"OS"=>["RouterOS 6.45.9"],
         "/interface pppoe-client"=>["add disabled=no interface=ether2 name=pppoe-user password=password service-name=internet user=user"],
         "/system identity"=>["set name=mikrotik_hostname"]})
    end

    it 'correctly with several terse values' do
      data = "# jul/17/2020 14:12:53 by RouterOS 6.45.9\n"
      data << "# software id = \n"
      data << "#\n"
      data << "#\n"
      data << "#\n"
      data << "/interface ovpn-client add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out1 password=password user=user\n"
      data << "/interface ovpn-client add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out2 password=password user=user\n"
      result = aux_mikrotik.export_to_hash(data)
      expect(result).to eq(
        {"OS"=>["RouterOS 6.45.9"],
         "/interface ovpn-client" => ["add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out1 password=password user=user", "add connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out2 password=password user=user"]
        })
    end
  end

  context 'converts settings to hash' do
    it 'handles nil' do
      result = aux_mikrotik.values_to_hash(nil)
      expect(result).to eq({})
    end

    it 'handles empty string' do
      result = aux_mikrotik.values_to_hash('')
      expect(result).to eq({})
    end

    it 'correctly with several values' do
      result = aux_mikrotik.export_to_hash('add connect-to=10.99.99.99 name=l2tp-hm password=123 user=l2tp-hm')
      expect(result).to eq({})
    end
  end


  context 'deals with OS details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves OS correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 OS: RouterOS 6.45.9')
      expect(aux_mikrotik).to receive(:report_host).with({:host=>"127.0.0.1", :os_flavor=>"6.45.9", :os_name=>"RouterOS"})
      expect(aux_mikrotik).to receive(:report_host).with({:host=>"127.0.0.1", :os_name=>'Mikrotik'})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        '# jul/17/2020 14:12:53 by RouterOS 6.45.9',
        "config.txt", "MikroTik Configuration"
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        '# jul/17/2020 14:12:53 by RouterOS 6.45.9'
      )
    end

    it 'saves hostname correct' do
      expect(aux_mikrotik).to receive(:report_host).with({:host=>"127.0.0.1", :os_name=>'Mikrotik'})
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :name=>"mikrotik_hostname", :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/system identity\nset name=mikrotik_hostname",
        "config.txt", "MikroTik Configuration"
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/system identity\nset name=mikrotik_hostname",
      )
    end

  end 

  context 'deals with OpenVPN Client details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves non-disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161  Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out1 with username user and password password')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface ovpn-client\nadd connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out1 password=password user=user",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1194,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'openvpn',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'user',
          private_data: "password",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface ovpn-client\nadd connect-to=10.99.99.98 mac-address=FE:45:B0:31:4A:34 name=ovpn-out1 password=password user=user"
      )
    end

    it 'saves disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 disabled Open VPN Client to 10.99.99.98 on mac FE:45:B0:31:4A:34 named ovpn-out3 with username user and password password')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface ovpn-client\nadd connect-to=10.99.99.98 disabled=yes mac-address=FE:45:B0:31:4A:34 name=ovpn-out3 password=password user=user",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1194,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'openvpn',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'user',
          private_data: "password",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface ovpn-client\nadd connect-to=10.99.99.98 disabled=yes mac-address=FE:45:B0:31:4A:34 name=ovpn-out3 password=password user=user",
      )
    end
  end 

  context 'deals with PPPoE Client details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves non-disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161  PPPoE Client on ether2 named pppoe-user and service name internet with username user and password password')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface pppoe-client\nadd disabled=no interface=ether2 name=pppoe-user password=password service-name=internet user=user",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'pppoe',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'user',
          private_data: "password",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface pppoe-client\nadd disabled=no interface=ether2 name=pppoe-user password=password service-name=internet user=user",
      )
    end

    it 'saves disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 disabled PPPoE Client on ether2 named pppoe-user and service name internet with username user and password password')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface pppoe-client\nadd interface=ether2 name=pppoe-user password=password service-name=internet user=user",
        "config.txt", "MikroTik Configuration"
      )  
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'pppoe',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'user',
          private_data: "password",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface pppoe-client\nadd interface=ether2 name=pppoe-user password=password service-name=internet user=user",
      )
    end
  end

  context 'deals with L2TP Client details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves non-disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161  L2TP Client to 10.99.99.99 named l2tp-hm with username l2tp-hm and password 123')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface l2tp-client\nadd disabled=no connect-to=10.99.99.99 name=l2tp-hm password=123 user=l2tp-hm",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1701,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'l2tp',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'l2tp-hm',
          private_data: "123",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface l2tp-client\nadd disabled=no connect-to=10.99.99.99 name=l2tp-hm password=123 user=l2tp-hm",
      )
    end

    it 'saves disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 disabled L2TP Client to 10.99.99.99 named l2tp-hm with username l2tp-hm and password 123')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface l2tp-client\nadd connect-to=10.99.99.99 name=l2tp-hm password=123 user=l2tp-hm",
        "config.txt", "MikroTik Configuration"
      )  
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1701,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'l2tp',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'l2tp-hm',
          private_data: "123",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface l2tp-client\nadd connect-to=10.99.99.99 name=l2tp-hm password=123 user=l2tp-hm",
      )
    end
  end

  context 'deals with PPTP Client details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves non-disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161  PPTP Client to 10.99.99.99 named pptp-hm with username pptp-hm and password 123')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface pptp-client\nadd connect-to=10.99.99.99 disabled=no name=pptp-hm password=123 user=pptp-hm",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1723,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'pptp',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'pptp-hm',
          private_data: "123",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface pptp-client\nadd connect-to=10.99.99.99 disabled=no name=pptp-hm password=123 user=pptp-hm",
      )
    end

    it 'saves disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 disabled PPTP Client to 10.99.99.99 named pptp-hm with username pptp-hm and password 123')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface pptp-client\nadd connect-to=10.99.99.99 name=pptp-hm password=123 user=pptp-hm",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1723,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'pptp',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'pptp-hm',
          private_data: "123",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface pptp-client\nadd connect-to=10.99.99.99 name=pptp-hm password=123 user=pptp-hm",
      )
    end
  end

  context 'deals with SNMP details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves RW correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 SNMP community write with password write and write access')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/snmp community\nadd addresses=::/0 authentication-password=write name=write write-access=yes",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          access_level: 'RW',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          private_data: "write",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/snmp community\nadd addresses=::/0 authentication-password=write name=write write-access=yes",
      )
    end

    it 'saves RO correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 SNMP community read with password read and read only')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/snmp community\nadd addresses=::/0 authentication-password=read name=read",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          private_data: "read",
          access_level: 'RO',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/snmp community\nadd addresses=::/0 authentication-password=read name=read",
      )
    end

    it 'saves v3 RO correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 SNMP community v3 with password 0123456789(SHA1), encryption password 9876543210(AES) and read only')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/snmp community\nadd addresses=::/0 authentication-password=0123456789 authentication-protocol=SHA1 encryption-password=9876543210 encryption-protocol=AES name=v3",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          access_level: 'RO',
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          private_data: "v3",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/snmp community\nadd addresses=::/0 authentication-password=0123456789 authentication-protocol=SHA1 encryption-password=9876543210 encryption-protocol=AES name=v3",
      )
    end
  end

  context 'deals with SMB user details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves non-disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161  SMB Username mtuser and password mtpasswd')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/ip smb users\nadd name=mtuser password=mtpasswd read-only=no",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'smb',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'mtuser',
          private_data: "mtpasswd",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/ip smb users\nadd name=mtuser password=mtpasswd read-only=no",
      )
    end

    it 'saves disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 disabled SMB Username disableduser and password disabledpasswd with RO only access')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/ip smb users\nadd disabled=yes name=disableduser password=disabledpasswd",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          access_level: 'RO',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'smb',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'disableduser',
          private_data: "disabledpasswd",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/ip smb users\nadd disabled=yes name=disableduser password=disabledpasswd",
      )
    end
  end

  context 'deals with SMTP User details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves non-disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 SMTP Username smtpuser and password smtppassword for 1.1.1.1:25')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/tool e-mail\nset address=1.1.1.1 from=router@router.com password=smtppassword user=smtpuser",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "1.1.1.1",
          port: 25,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'smtp',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'smtpuser',
          private_data: "smtppassword",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/tool e-mail\nset address=1.1.1.1 from=router@router.com password=smtppassword user=smtpuser",
      )
    end
  end

  context 'deals with PPP tunnel bridging details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves non-disabled correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161  PPP tunnel bridging named ppp1 with profile name ppp_bridge and password password')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/ppp secret\nadd name=ppp1 password=password profile=ppp_bridge",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: '',
          private_data: "password",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/ppp secret\nadd name=ppp1 password=password profile=ppp_bridge",
      )
    end
  end

  context 'deals with Wireless details' do
    before(:example) do
      expect(aux_mikrotik).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves WEP correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 Wireless AP wepwifi with WEP password 0123456789 with WEP password 0987654321 with WEP password 1234509876 with WEP password 0192837645')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface wireless security-profiles\nadd mode=static-keys-required name=wepwifi static-key-0=0123456789 static-key-1=0987654321 static-key-2=1234509876 static-key-3=0192837645 supplicant-identity=MikroTik",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          private_data: "0123456789",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          private_data: "0987654321",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          private_data: "1234509876",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          private_data: "0192837645",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface wireless security-profiles\nadd mode=static-keys-required name=wepwifi static-key-0=0123456789 static-key-1=0987654321 static-key-2=1234509876 static-key-3=0192837645 supplicant-identity=MikroTik",
      )
    end
    it 'saves WPA correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 Wireless AP wpawifi with WPA password presharedkey')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface wireless security-profiles\nadd authentication-types=wpa-psk mode=dynamic-keys name=wpawifi supplicant-identity=MikroTik wpa-pre-shared-key=presharedkey",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          private_data: "presharedkey",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface wireless security-profiles\nadd authentication-types=wpa-psk mode=dynamic-keys name=wpawifi supplicant-identity=MikroTik wpa-pre-shared-key=presharedkey",
      )
    end
    it 'saves WPA2 correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 Wireless AP wpa2wifi with WPA2 password presharedkey')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface wireless security-profiles\nadd authentication-types=wpa2-psk mode=dynamic-keys name=wpa2wifi supplicant-identity=MikroTik wpa2-pre-shared-key=presharedkey",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          private_data: "presharedkey",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface wireless security-profiles\nadd authentication-types=wpa2-psk mode=dynamic-keys name=wpa2wifi supplicant-identity=MikroTik wpa2-pre-shared-key=presharedkey",
      )
    end
    it 'saves WPA-EAP correct' do
      expect(aux_mikrotik).to receive(:print_good).with('127.0.0.1:161 Wireless AP wpaeapwifi with WPA2-EAP username username password password')
      expect(aux_mikrotik).to receive(:report_host).with({:host => '127.0.0.1', :os_name=>"Mikrotik"})
      expect(aux_mikrotik).to receive(:store_loot).with(
        "mikrotik.config", "text/plain", "127.0.0.1",
        "/interface wireless security-profiles\nadd authentication-types=wpa2-eap mode=dynamic-keys mschapv2-password=password mschapv2-username=username name=wpaeapwifi supplicant-identity=MikroTik",
        "config.txt", "MikroTik Configuration"
      )
      expect(aux_mikrotik).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/mikrotik_dummy",
          username: 'username',
          private_data: "password",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_mikrotik.mikrotik_export_config_eater('127.0.0.1',161,
        "/interface wireless security-profiles\nadd authentication-types=wpa2-eap mode=dynamic-keys mschapv2-password=password mschapv2-username=username name=wpaeapwifi supplicant-identity=MikroTik",
      )
    end
  end

end
