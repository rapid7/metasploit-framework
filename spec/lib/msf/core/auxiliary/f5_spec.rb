# -*- coding: binary -*-

require 'spec_helper'


RSpec.describe Msf::Auxiliary::F5 do
  class DummyF5Class
    include Msf::Auxiliary::F5
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
      'auxiliary/scanner/snmp/f5_dummy'
    end

    def myworkspace
      raise StandardError, 'This method needs to be stubbed.'
    end
  end

  subject(:aux_f5) { DummyF5Class.new }

  let!(:workspace) { FactoryBot.create(:mdm_workspace) }

  context '#create_credential_and_login' do
    let(:session) { FactoryBot.create(:mdm_session) }

    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace) }

    let(:user) { FactoryBot.create(:mdm_user) }

    subject(:test_object) { DummyF5Class.new }

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

  context '#f5_config_eater' do
    before(:example) do
      expect(aux_f5).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'deals with user passwords' do
      data = "auth user admin {\n"
      data << "   description \"Admin User\"\n"
      data << "   encrypted-password $6$4FAWSZLi$VeSaxPM2/D1JOhMRN/GMkt5wHcbIVKaIC2g765ZD0VA9ZEEm8iyK40/ncGrZIGyJyJF4ivkScNZ59HWAIKMML/\n"
      data << "   partition Common\n"
      data << "   partition-access {\n"
      data << "       all-partitions {\n"
      data << "           role admin\n"
      data << "       }\n"
      data << "   }\n"
      data << "   shell none\n"
      data << '}'
      expect(aux_f5).to receive(:print_good).with("127.0.0.1:161 Username 'admin' with description 'Admin User' and shell none with hash $6$4FAWSZLi$VeSaxPM2/D1JOhMRN/GMkt5wHcbIVKaIC2g765ZD0VA9ZEEm8iyK40/ncGrZIGyJyJF4ivkScNZ59HWAIKMML/")
      expect(aux_f5).to receive(:store_loot).with(
        'f5.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'F5 Configuration'
      )
      expect(aux_f5).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/f5_dummy',
          jtr_format: 'sha512,crypt',
          username: 'admin',
          private_data: '$6$4FAWSZLi$VeSaxPM2/D1JOhMRN/GMkt5wHcbIVKaIC2g765ZD0VA9ZEEm8iyK40/ncGrZIGyJyJF4ivkScNZ59HWAIKMML/',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_f5.f5_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with system keys' do
      data = "master-key hash  <EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==>\n"
      data << ' previous hash    <EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==>'

      expect(aux_f5).to receive(:print_good).with('127.0.0.1:161 F5 master-key hash EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==')
      expect(aux_f5).to receive(:print_good).with('127.0.0.1:161 F5 previous hash EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==')
      expect(aux_f5).to receive(:store_loot).with(
        'f5.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'F5 Configuration'
      )
      expect(aux_f5).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/f5_dummy',
          private_data: 'EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==',
          jtr_format: '',
          username: 'F5 master-key hash',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      expect(aux_f5).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/f5_dummy',
          private_data: 'EFt+B7/aTWwPwLoMd8KLYW4JB3K5B6301k4pGsoWnZEb2yUbvEJgNU3FcLHo0S4QvdrwVcKrNtHLzebC7HizHQ==',
          jtr_format: '',
          username: 'F5 previous hash',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_f5.f5_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with host information' do
      data = "cm device /Common/f5bigip.ragegroup.com {\n"
      data << "    active-modules { \"BIG-IP, VE Trial|VTFAAAA-AAAAAAA|Rate Shaping|External Interface and Network HSM, VE|SDN Services, VE|SSL, Forward Proxy, VE|BIG-IP VE, Multicast Routing|APM, Limited|SSL, VE|DNS (1K QPS), VE|Routing Bundle, VE|ASM, VE|Crytpo Offload, VE, Tier 1 (25M - 200M)|Max Compression, VE|AFM, VE|DNSSEC|Anti-Virus Checks|Base Endpoint Security Checks|Firewall Checks|Network Access|Secure Virtual Keyboard|APM, Web Application|Machine Certificate Checks|Protected Workspace|Remote Desktop|App Tunnel|VE, Carrier Grade NAT (AFM ONLY)|PSM, VE\" }\n"
      data << "    base-mac 00:11:11:a1:a1:a1\n"
      data << "    build 0.0.9\n"
      data << "    cert /Common/dtdi.crt\n"
      data << "    chassis-id 164aaf79-aace-3494-1237671446c7\n"
      data << "    configsync-ip 10.10.10.222\n"
      data << "    edition \"Point Release 2\"\n"
      data << "    hostname f5bigip.home.com\n"
      data << "    key /Common/dtdi.key\n"
      data << "    management-ip 1.1.1.1\n"
      data << "    marketing-name \"BIG-IP Virtual Edition\"\n"
      data << "    platform-id Z100\n"
      data << "    product BIG-IP\n"
      data << "    self-device true\n"
      data << "    time-zone America/Los_Angeles\n"
      data << "    version 15.1.0.2\n"
      data << '}'

      expect(aux_f5).to receive(:print_good).with('127.0.0.1:161 Hostname: f5bigip.home.com')
      expect(aux_f5).to receive(:print_good).with('127.0.0.1:161 MAC Address: 00:11:11:a1:a1:a1')
      expect(aux_f5).to receive(:print_good).with('127.0.0.1:161 Management IP: 1.1.1.1')
      expect(aux_f5).to receive(:print_good).with('127.0.0.1:161 Product BIG-IP')
      expect(aux_f5).to receive(:print_good).with('127.0.0.1:161 OS Version: 15.1.0.2')
      expect(aux_f5).to receive(:store_loot).with(
        'f5.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'F5 Configuration'
      )
      aux_f5.f5_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with SSL Keys' do
      data = "sys file ssl-key /Common/f5_api_com.key {\n"
      data << "    cache-path /config/filestore/files_d/Common_d/certificate_key_d/:Common:f5_api_com.key_63086_1\n"
      data << "    passphrase $M$iE$cIdy72xi7Xbk3kazSrpdfscd+oD1pdsXJbwhvhMPiss4Iw0RKIJQS/CuSReZl/+kseKpPCNpBWNWOOaBCwlQ0v4sl7ZUkxCymh5pfFNAjhc=\n"
      data << "    revision 1\n"
      data << "    source-path file:///config/ssl/ssl.key/f5_api_com.key\n"
      data << '}'
      expect(aux_f5).to receive(:print_good).with("127.0.0.1:161 SSL Key '/Common/f5_api_com.key' and hash $M$iE$cIdy72xi7Xbk3kazSrpdfscd+oD1pdsXJbwhvhMPiss4Iw0RKIJQS/CuSReZl/+kseKpPCNpBWNWOOaBCwlQ0v4sl7ZUkxCymh5pfFNAjhc= for /config/ssl/ssl.key/f5_api_com.key")
      expect(aux_f5).to receive(:store_loot).with(
        'f5.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'F5 Configuration'
      )
      expect(aux_f5).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/f5_dummy',
          private_data: '$M$iE$cIdy72xi7Xbk3kazSrpdfscd+oD1pdsXJbwhvhMPiss4Iw0RKIJQS/CuSReZl/+kseKpPCNpBWNWOOaBCwlQ0v4sl7ZUkxCymh5pfFNAjhc=',
          jtr_format: 'F5-Secure-Vault',
          username: '/Common/f5_api_com.key',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_f5.f5_config_eater('127.0.0.1', 161, data)
    end

    it 'deals with SNMP' do
      data = "sys snmp {\n"
      data << "    communities {\n"
      data << "        comm-public {\n"
      data << "            community-name public\n"
      data << "            source default\n"
      data << "        }\n"
      data << "        rw {\n"
      data << "            access rw\n"
      data << "            community-name rwcommunity\n"
      data << "        }\n"
      data << "    }\n"
      data << '}'

      expect(aux_f5).to receive(:print_good).with("127.0.0.1:161 SNMP Community 'public' with RO access")
      expect(aux_f5).to receive(:print_good).with("127.0.0.1:161 SNMP Community 'rwcommunity' with RW access")
      expect(aux_f5).to receive(:store_loot).with(
        'f5.config', 'text/plain', '127.0.0.1', data, 'config.txt', 'F5 Configuration'
      )
      expect(aux_f5).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          jtr_format: '',
          access_level: 'RO',
          module_fullname: 'auxiliary/scanner/snmp/f5_dummy',
          private_data: 'public',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      expect(aux_f5).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          access_level: 'RW',
          jtr_format: '',
          module_fullname: 'auxiliary/scanner/snmp/f5_dummy',
          private_data: 'rwcommunity',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_f5.f5_config_eater('127.0.0.1', 161, data)
    end
  end
end
