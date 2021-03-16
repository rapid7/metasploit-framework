# -*- coding: binary -*-

require 'spec_helper'


RSpec.describe Msf::Auxiliary::Arista do
  class DummyAristaClass
    include Msf::Auxiliary::Arista
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
      'auxiliary/scanner/snmp/arista_dummy'
    end

    def myworkspace
      raise StandardError, 'This method needs to be stubbed.'
    end
  end

  subject(:aux_arista) { DummyAristaClass.new }

  let!(:workspace) { FactoryBot.create(:mdm_workspace) }

  context '#create_credential_and_login' do
    let(:session) { FactoryBot.create(:mdm_session) }

    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace) }

    let(:user) { FactoryBot.create(:mdm_user) }

    subject(:test_object) { DummyAristaClass.new }

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

  context '#arista_eos_config_eater' do
    before(:example) do
      expect(aux_arista).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'deals with model and version' do
      expect(aux_arista).to receive(:print_good).with('127.0.0.1:161 Hostname: aristaveos, Device: vEOS, OS: EOS, Version: 4.19.10M')
      expect(aux_arista).to receive(:store_loot).with(
        'arista.eos.config', 'text/plain', '127.0.0.1', '! device: aristaveos (vEOS, EOS-4.19.10M)', 'config.txt', 'Arista EOS Configuration'
      )
      aux_arista.arista_eos_config_eater('127.0.0.1', 161, '! device: aristaveos (vEOS, EOS-4.19.10M)')
    end

    it 'deals with hostname' do
      expect(aux_arista).to receive(:print_good).with('127.0.0.1:161 Hostname: aristaveos')
      expect(aux_arista).to receive(:store_loot).with(
        'arista.eos.config', 'text/plain', '127.0.0.1', 'hostname aristaveos', 'config.txt', 'Arista EOS Configuration'
      )
      aux_arista.arista_eos_config_eater('127.0.0.1', 161, 'hostname aristaveos')
    end

    it 'deals with enable passwords' do
      expect(aux_arista).to receive(:print_good).with('127.0.0.1:161 Enable hash: $6$jemN09cUdoLRim6i$Mvl2Fog/VZ7ktxyLSVDR1KnTTTPSMHU3WD.G/kxwgODdsc3d7S1aSNJX/DJmQI3nyrYnEw4lsmoKPGClFJ9hH1')
      expect(aux_arista).to receive(:store_loot).with(
        'arista.eos.config', 'text/plain', '127.0.0.1', 'enable secret sha512 $6$jemN09cUdoLRim6i$Mvl2Fog/VZ7ktxyLSVDR1KnTTTPSMHU3WD.G/kxwgODdsc3d7S1aSNJX/DJmQI3nyrYnEw4lsmoKPGClFJ9hH1', 'config.txt', 'Arista EOS Configuration'
      )
      expect(aux_arista).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/arista_dummy',
          username: 'enable',
          jtr_format: 'sha512,crypt',
          private_data: '$6$jemN09cUdoLRim6i$Mvl2Fog/VZ7ktxyLSVDR1KnTTTPSMHU3WD.G/kxwgODdsc3d7S1aSNJX/DJmQI3nyrYnEw4lsmoKPGClFJ9hH1',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_arista.arista_eos_config_eater('127.0.0.1', 161, 'enable secret sha512 $6$jemN09cUdoLRim6i$Mvl2Fog/VZ7ktxyLSVDR1KnTTTPSMHU3WD.G/kxwgODdsc3d7S1aSNJX/DJmQI3nyrYnEw4lsmoKPGClFJ9hH1')
    end

    it 'deals with aaa root secret' do
      expect(aux_arista).to receive(:print_good).with("127.0.0.1:161 AAA Username 'root' with Hash: $6$Rnanb2dQsVy2H3QL$DEYDZMy6j6KK4XK62Uh.3U3WXxK5XJvn8Zd5sm36T7BVKHS5EmIcQV.EN1X1P1ZO099S0lkxpvEGzA9yK5PQF.")
      expect(aux_arista).to receive(:store_loot).with(
        'arista.eos.config', 'text/plain', '127.0.0.1', 'aaa root secret sha512 $6$Rnanb2dQsVy2H3QL$DEYDZMy6j6KK4XK62Uh.3U3WXxK5XJvn8Zd5sm36T7BVKHS5EmIcQV.EN1X1P1ZO099S0lkxpvEGzA9yK5PQF.', 'config.txt', 'Arista EOS Configuration'
      )
      expect(aux_arista).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/arista_dummy',
          username: 'root',
          jtr_format: 'sha512,crypt',
          private_data: '$6$Rnanb2dQsVy2H3QL$DEYDZMy6j6KK4XK62Uh.3U3WXxK5XJvn8Zd5sm36T7BVKHS5EmIcQV.EN1X1P1ZO099S0lkxpvEGzA9yK5PQF.',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_arista.arista_eos_config_eater('127.0.0.1', 161, 'aaa root secret sha512 $6$Rnanb2dQsVy2H3QL$DEYDZMy6j6KK4XK62Uh.3U3WXxK5XJvn8Zd5sm36T7BVKHS5EmIcQV.EN1X1P1ZO099S0lkxpvEGzA9yK5PQF.')
    end
  end

  context 'deals with user details' do
    before(:example) do
      expect(aux_arista).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'deals with roles and sha512 passwords' do
      expect(aux_arista).to receive(:print_good).with("127.0.0.1:161 Username 'admin' with privilege 15, Role network-admin, and Hash: $6$Ei2bjrcTCGPOjSkk$7S.XSTZqdRVXILbUUDcRPCxzyfqEFYzg6HfL0BHXvriETX330MT.KObHLkGx7n9XZRVWBr68ZsKfvzvxYCvj61")
      expect(aux_arista).to receive(:store_loot).with(
        'arista.eos.config', 'text/plain', '127.0.0.1', 'username admin privilege 15 role network-admin secret sha512 $6$Ei2bjrcTCGPOjSkk$7S.XSTZqdRVXILbUUDcRPCxzyfqEFYzg6HfL0BHXvriETX330MT.KObHLkGx7n9XZRVWBr68ZsKfvzvxYCvj61', 'config.txt', 'Arista EOS Configuration'
      )
      expect(aux_arista).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/arista_dummy',
          username: 'admin',
          jtr_format: 'sha512,crypt',
          private_data: '$6$Ei2bjrcTCGPOjSkk$7S.XSTZqdRVXILbUUDcRPCxzyfqEFYzg6HfL0BHXvriETX330MT.KObHLkGx7n9XZRVWBr68ZsKfvzvxYCvj61',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_arista.arista_eos_config_eater('127.0.0.1', 161, 'username admin privilege 15 role network-admin secret sha512 $6$Ei2bjrcTCGPOjSkk$7S.XSTZqdRVXILbUUDcRPCxzyfqEFYzg6HfL0BHXvriETX330MT.KObHLkGx7n9XZRVWBr68ZsKfvzvxYCvj61')
    end

    it 'deals with no roles and md5 passwords' do
      expect(aux_arista).to receive(:print_good).with("127.0.0.1:161 Username 'bob' with privilege 15, and Hash: $1$EGQJlod0$CdkMmW1FoiRgMfbLFD/kB/")
      expect(aux_arista).to receive(:store_loot).with(
        'arista.eos.config', 'text/plain', '127.0.0.1', 'username bob privilege 15 secret 5 $1$EGQJlod0$CdkMmW1FoiRgMfbLFD/kB/', 'config.txt', 'Arista EOS Configuration'
      )
      expect(aux_arista).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/arista_dummy',
          username: 'bob',
          jtr_format: 'md5',
          private_data: '$1$EGQJlod0$CdkMmW1FoiRgMfbLFD/kB/',
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_arista.arista_eos_config_eater('127.0.0.1', 161, 'username bob privilege 15 secret 5 $1$EGQJlod0$CdkMmW1FoiRgMfbLFD/kB/')
    end

    it 'deals with no roles and plaintext passwords' do
      expect(aux_arista).to receive(:print_good).with("127.0.0.1:161 Username 'un' with privilege 15, and Password: test")
      expect(aux_arista).to receive(:store_loot).with(
        'arista.eos.config', 'text/plain', '127.0.0.1', 'username un privilege 15 secret 0 test', 'config.txt', 'Arista EOS Configuration'
      )
      expect(aux_arista).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: 'auxiliary/scanner/snmp/arista_dummy',
          username: 'un',
          jtr_format: '',
          private_data: 'test',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_arista.arista_eos_config_eater('127.0.0.1', 161, 'username un privilege 15 secret 0 test')
    end
  end

  context 'deals with SNMP details' do
    before(:example) do
      expect(aux_arista).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
    it 'saves RW correct' do
      expect(aux_arista).to receive(:print_good).with('127.0.0.1:161 SNMP Community (rw): write')
      expect(aux_arista).to receive(:report_host).with({ host: '127.0.0.1', os_name: 'Arista EOS' })
      expect(aux_arista).to receive(:store_loot).with(
        'arista.eos.config', 'text/plain', '127.0.0.1',
        'snmp-server community write rw',
        'config.txt', 'Arista EOS Configuration'
      )
      expect(aux_arista).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          access_level: 'RW',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          jtr_format: '',
          module_fullname: 'auxiliary/scanner/snmp/arista_dummy',
          private_data: 'write',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_arista.arista_eos_config_eater('127.0.0.1', 161,
                                         'snmp-server community write rw')
    end
    it 'saves RO correct' do
      expect(aux_arista).to receive(:print_good).with('127.0.0.1:161 SNMP Community (ro): read')
      expect(aux_arista).to receive(:report_host).with({ host: '127.0.0.1', os_name: 'Arista EOS' })
      expect(aux_arista).to receive(:store_loot).with(
        'arista.eos.config', 'text/plain', '127.0.0.1',
        'snmp-server community read ro',
        'config.txt', 'Arista EOS Configuration'
      )
      expect(aux_arista).to receive(:create_credential_and_login).with(
        {
          address: '127.0.0.1',
          port: 161,
          protocol: 'udp',
          access_level: 'RO',
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          jtr_format: '',
          module_fullname: 'auxiliary/scanner/snmp/arista_dummy',
          private_data: 'read',
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      )
      aux_arista.arista_eos_config_eater('127.0.0.1', 161,
                                         'snmp-server community read ro')
    end
  end
end
