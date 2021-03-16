# -*- coding: binary -*-

require 'spec_helper'

RSpec.describe Msf::Auxiliary::VYOS do
  class DummyVYOSClass
    include Msf::Auxiliary::VYOS
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

    def vprint_good(_str = nil)
      raise StandardError, 'This method needs to be stubbed.'
    end

    def print_good(_str = nil)
      raise StandardError, 'This method needs to be stubbed.'
    end

    def print_bad(_str = nil)
      raise StandardError, 'This method needs to be stubbed.'
    end

    def store_cred(_hsh = nil)
      raise StandardError, 'This method needs to be stubbed.'
    end

    def fullname
      'auxiliary/scanner/snmp/vyos_dummy'
    end

    def myworkspace
      raise StandardError, 'This method needs to be stubbed.'
    end
  end

  subject(:aux_vyos) { DummyVYOSClass.new }

  let!(:workspace) { FactoryBot.create(:mdm_workspace) }

  context '#create_credential_and_login' do
    let(:session) { FactoryBot.create(:mdm_session) }

    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace) }

    let(:user) { FactoryBot.create(:mdm_user) }

    subject(:test_object) { DummyVYOSClass.new }

    let(:workspace) { FactoryBot.create(:mdm_workspace) }
    let(:service) { FactoryBot.create(:mdm_service, host: FactoryBot.create(:mdm_host, workspace: workspace)) }
    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace) }

    let(:login_data) do
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
    end

    it 'creates a Metasploit::Credential::Login' do
      expect { test_object.create_credential_and_login(login_data) }.to change { Metasploit::Credential::Login.count }.by(1)
    end
    it 'associates the Metasploit::Credential::Core with a task if passed' do
      login = test_object.create_credential_and_login(login_data.merge(task_id: task.id))
      expect(login.tasks).to include(task)
    end
  end

  context '#vyos_config_eater' do
    before(:example) do
      expect(aux_vyos).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'deals with v1.1.8 user passwords' do
      data = "login {\n"
      data << "user jsmith {\n"
      data << "        authentication {\n"
      data << "            encrypted-password $6$ELBrDuW7c/8$nN7MwUST8s8O0R6HMNu/iPoTQ1s..y8HTnXraJ7Hh4bHefRmjt/2U08ZckEw4FU034wbWaeCaB5hq7mC6fNXl/\n"
      data << "            plaintext-password \"\"\n"
      data << "        }\n"
      data << "        full-name \"John Smith\"\n"
      data << "        level operator\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Username 'jsmith' with level 'operator' with hash $6$ELBrDuW7c/8$nN7MwUST8s8O0R6HMNu/iPoTQ1s..y8HTnXraJ7Hh4bHefRmjt/2U08ZckEw4FU034wbWaeCaB5hq7mC6fNXl/")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          access_level: 'operator',
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: 'sha512,crypt',
          username: 'jsmith',
          private_data: '$6$ELBrDuW7c/8$nN7MwUST8s8O0R6HMNu/iPoTQ1s..y8HTnXraJ7Hh4bHefRmjt/2U08ZckEw4FU034wbWaeCaB5hq7mC6fNXl/',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with v1.3 user passwords' do
      data = "login {\n"
      data << "user jsmith {\n"
      data << "        authentication {\n"
      data << "            encrypted-password $6$ELBrDuW7c/8$nN7MwUST8s8O0R6HMNu/iPoTQ1s..y8HTnXraJ7Hh4bHefRmjt/2U08ZckEw4FU034wbWaeCaB5hq7mC6fNXl/\n"
      data << "            plaintext-password \"\"\n"
      data << "        }\n"
      data << "        full-name \"John Smith\"\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Username 'jsmith' with level 'admin' with hash $6$ELBrDuW7c/8$nN7MwUST8s8O0R6HMNu/iPoTQ1s..y8HTnXraJ7Hh4bHefRmjt/2U08ZckEw4FU034wbWaeCaB5hq7mC6fNXl/")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          access_level: 'admin',
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: 'sha512,crypt',
          username: 'jsmith',
          private_data: '$6$ELBrDuW7c/8$nN7MwUST8s8O0R6HMNu/iPoTQ1s..y8HTnXraJ7Hh4bHefRmjt/2U08ZckEw4FU034wbWaeCaB5hq7mC6fNXl/',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with file not found' do
      data = "No such file or directory"
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with permission denied' do
      data = "cat: /config/config.boot: Permission denied"
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with v1.1.8 admin password' do
      data = "login {\n"
      data << "    user vyos {\n"
      data << "        authentication {\n"
      data << "            encrypted-password $1$5HsQse2v$VQLh5eeEp4ZzGmCG/PRBA1\n"
      data << "            plaintext-password \"\"\n"
      data << "        }\n"
      data << "        level admin\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Username 'vyos' with level 'admin' with hash $1$5HsQse2v$VQLh5eeEp4ZzGmCG/PRBA1")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          access_level: 'admin',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: 'md5',
          username: 'vyos',
          private_data: '$1$5HsQse2v$VQLh5eeEp4ZzGmCG/PRBA1',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with v1.3 admin password' do
      data = "login {\n"
      data << "    user vyos {\n"
      data << "        authentication {\n"
      data << "            encrypted-password $1$5HsQse2v$VQLh5eeEp4ZzGmCG/PRBA1\n"
      data << "            plaintext-password \"\"\n"
      data << "        }\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Username 'vyos' with level 'admin' with hash $1$5HsQse2v$VQLh5eeEp4ZzGmCG/PRBA1")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          access_level: 'admin',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: 'md5',
          username: 'vyos',
          private_data: '$1$5HsQse2v$VQLh5eeEp4ZzGmCG/PRBA1',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with admin password with no plaintext field' do
      data = "login {\n"
      data << "    user vyos {\n"
      data << "        authentication {\n"
      data << "            encrypted-password $1$5HsQse2v$VQLh5eeEp4ZzGmCG/PRBA1\n"
      data << "        }\n"
      data << "        level admin\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Username 'vyos' with level 'admin' with hash $1$5HsQse2v$VQLh5eeEp4ZzGmCG/PRBA1")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          access_level: 'admin',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: 'md5',
          username: 'vyos',
          private_data: '$1$5HsQse2v$VQLh5eeEp4ZzGmCG/PRBA1',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with masked passwords' do
      data = "login {\n"
      data << "    user vyos {\n"
      data << "        authentication {\n"
      data << "            encrypted-password ****************\n"
      data << "            plaintext-password \"\"\n"
      data << "        }\n"
      data << "        level admin\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Username 'vyos' with level 'admin'")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          access_level: 'admin',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          username: 'vyos',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with SNMP ro communities' do
      data = "service {\n"
      data << "    snmp {\n"
      data << "        community ro {\n"
      data << "            authorization ro\n"
      data << "        }\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 SNMP Community 'ro' with ro access")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          access_level: 'ro',
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: '',
          private_data: 'ro',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with SNMP rw communities' do
      data = "service {\n"
      data << "    snmp {\n"
      data << "        community write {\n"
      data << "            authorization rw\n"
      data << "        }\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 SNMP Community 'write' with rw access")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          access_level: 'rw',
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: '',
          private_data: 'write',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with OS Versions old style' do
      data = "/* Release version: VyOS 1.1.8 */"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 OS Version: VyOS 1.1.8")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with OS Versions new style' do
      data = "// Release version: VyOS 1.3-rolling-202008270118"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 OS Version: VyOS 1.3-rolling-202008270118")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with host names' do
      data = "system {\n"
      data << "    host-name vyos\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Hostname: vyos")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with static ethernet addresses' do
      data = "interfaces {\n"
      data << "    ethernet eth0 {\n"
      data << "        address 1.1.1.1/8\n"
      data << "        hw-id 00:00:aa:ff:99:99:99\n"
      data << "    }"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Interface eth0 (00:00:aa:ff:99:99) - 1.1.1.1")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with static ethernet addresses with description' do
      data = "interfaces {\n"
      data << "    ethernet eth0 {\n"
      data << "        address 1.1.1.1/8\n"
      data << "        description \"outside\"\n"
      data << "        hw-id 00:00:aa:ff:99:99:99\n"
      data << "    }"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Interface eth0 (00:00:aa:ff:99:99) - 1.1.1.1 with description: outside")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with wireless server' do
      data =  "interfaces {\n"
      data << "  wireless wlan0 {\n"
      data << "        address 192.168.2.1/24\n"
      data << "        channel 1\n"
      data << "        mode n\n"
      data << "        security {\n"
      data << "            wpa {\n"
      data << "                cipher CCMP\n"
      data << "                mode wpa2\n"
      data << "                passphrase \"12345678\"\n"
      data << "            }\n"
      data << "        }\n"
      data << "        ssid \"TEST\"\n"
      data << "        type access-point\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Wireless access-point 'TEST' with password: 12345678")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 1,
          protocol: 'tcp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'wireless AP',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: '',
          private_data: '12345678',
          username: 'TEST',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with wireless server with radius' do
      data =  "interfaces {\n"
      data << "  wireless wlan0 {\n"
      data << "        address 192.168.2.1/24\n"
      data << "        channel 1\n"
      data << "        mode n\n"
      data << "        security {\n"
      data << "            wpa {\n"
      data << "                cipher CCMP\n"
      data << "                mode wpa2\n"
      data << "                radius {\n"
      data << "                    server 192.168.3.10 {\n"
      data << "                        key 'VyOSPassword'\n"
      data << "                        port 1812\n"
      data << "                    }\n"
      data << "                }\n"
      data << "            }\n"
      data << "        }\n"
      data << "        ssid \"Enterprise-TEST\"\n"
      data << "        type access-point\n"
      data << "    }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Wireless access-point 'Enterprise-TEST' with radius password: VyOSPassword to 192.168.3.101812")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 1,
          protocol: 'tcp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'wireless AP',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: '',
          private_data: 'VyOSPassword',
          username: 'Enterprise-TEST',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with wireless client' do
      data =  "interfaces {\n"
      data << "  wireless wlan0 {\n"
      data << "    address dhcp\n"
      data << "    security {\n"
      data << "      wpa {\n"
      data << "        passphrase \"12345678\"\n"
      data << "      }\n"
      data << "    }\n"
      data << "    ssid TEST\n"
      data << "    type station\n"
      data << "  }\n"
      data << "}"
      expect(aux_vyos).to receive(:print_good).with("127.0.0.1:161 Wireless station 'TEST' with password: 12345678")
      expect(aux_vyos).to receive(:vprint_good).with("127.0.0.1:161 Config saved to: ")
      expect(aux_vyos).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 1,
          protocol: 'tcp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'wireless',
          module_fullname: 'auxiliary/scanner/snmp/vyos_dummy',
          jtr_format: '',
          private_data: '12345678',
          username: 'TEST',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      expect(aux_vyos).to receive(:store_loot).with(
        'vyos.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'VyOS Configuration'
      )
      aux_vyos.vyos_config_eater('127.0.0.1', 161, data)
    end
  end
end
