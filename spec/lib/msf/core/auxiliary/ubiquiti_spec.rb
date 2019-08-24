# -*- coding: binary -*-
require 'spec_helper'

require 'msf/core/auxiliary/ubiquiti'
require 'bson'

RSpec.describe Msf::Auxiliary::Ubiquiti do
  class DummyClass
    include Msf::Auxiliary::Ubiquiti
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
      "auxiliary/scanner/snmp/ubiquiti_dummy"
    end
    def myworkspace
      raise StandardError.new("This method needs to be stubbed.")
    end
  end
  
  subject(:aux_unifi) { DummyClass.new }
  
  let!(:workspace) { FactoryBot.create(:mdm_workspace) }
    
  context '#create_credential_and_login' do
    
    let(:session) { FactoryBot.create(:mdm_session) }

    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace)}

    let(:user) { FactoryBot.create(:mdm_user)}

    subject(:test_object) { DummyClass.new }
    
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

  context 'converts bson to json' do
    it 'handles nil' do
      result = aux_unifi.bson_to_json(nil)
      expect(result).to eq({})
    end

    it 'handles empty string' do
      result = aux_unifi.bson_to_json('')
      expect(result).to eq({})
    end

    it 'correctly with admin and radius' do
      data = BSON::Document["__cmd","select", "collection","admin"].to_bson.to_s
      data << BSON::Document["_id",BSON::ObjectId('5c7f22af3815ce2087d1d9ce'), "name","administrator"].to_bson.to_s
      data << BSON::Document["__cmd","select", "collection","radiusprofile"].to_bson.to_s
      data << BSON::Document["_id",BSON::ObjectId('5c7f22af3815ce2087d1d9cf'), "attr_no_delete",true].to_bson.to_s
      result = aux_unifi.bson_to_json(data)
      expect(result).to eq({"admin"=>[{"_id"=>BSON::ObjectId('5c7f22af3815ce2087d1d9ce'), "name"=>"administrator"}],"radiusprofile"=>[{"_id"=>BSON::ObjectId('5c7f22af3815ce2087d1d9cf'), "attr_no_delete"=>true}]})
    end
  end

  context 'deals with admin'  do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'users' do
      expect(aux_unifi).to receive(:print_good).with('Admin user adminuser with email admin@admin.com found with password hash $6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V.')
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Ubiquiti Unifi'})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
       {"admin"=>[{"_id"=>BSON::ObjectId('5c7f23af3825ce2067a1d9ce'), "name"=>"adminuser", "email"=>"admin@admin.com", "x_shadow"=>"$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V.", "time_created"=>1551825823, "last_site_name"=>"default", "ubic_name"=>"admin@admin.com", "ubic_uuid"=>"c23da064-3f4d-282f-1dc9-7e25f9c6812c", "ui_settings"=>{"dashboardConfig"=>{"lastActiveDashboardId"=>"2c7f2d213813ce2487d1ac38", "dashboards"=>{"3c7f678a3815ce2021d1d9c7"=>{"order"=>1}, "5b4f2d269115ce2087d1abb9"=>{}}}}}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )
      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V.",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED,
          username: 'adminuser'
        }
      )
      aux_unifi.unifi_config_eater('127.0.0.1',161,
        {"admin"=>[{"_id"=>BSON::ObjectId('5c7f23af3825ce2067a1d9ce'), "name"=>"adminuser", "email"=>"admin@admin.com", "x_shadow"=>"$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V.", "time_created"=>1551825823, "last_site_name"=>"default", "ubic_name"=>"admin@admin.com", "ubic_uuid"=>"c23da064-3f4d-282f-1dc9-7e25f9c6812c", "ui_settings"=>{"dashboardConfig"=>{"lastActiveDashboardId"=>"2c7f2d213813ce2487d1ac38", "dashboards"=>{"3c7f678a3815ce2021d1d9c7"=>{"order"=>1}, "5b4f2d269115ce2087d1abb9"=>{}}}}}]}
      )
    end
  end
    
  context 'deals with radius configurations' do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end
      
    it 'with internal configurations' do
      expect(aux_unifi).to receive(:print_good).with("Radius server: 192.168.0.1:1812 with secret 'supersecret'")
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Ubiquiti Unifi'})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"radiusprofile"=>[{"_id"=>BSON::ObjectId('2c7a318c38c5ce2f86d179cb'), "attr_no_delete"=>true, "attr_hidden_id"=>"Default", "name"=>"Default", "site_id"=>"3c7f226b2315be2087a1d5b2", "use_usg_auth_server"=>true, "auth_servers"=>[{"ip"=>"192.168.0.1", "port"=>1812, "x_secret"=>"supersecret"}], "acct_servers"=>[]}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )
      expect(aux_unifi).to receive(:report_service).with(
        {:host=>"192.168.0.1", :name=>"radius", :port=>1812, :proto=>"udp"}
      )
      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "192.168.0.1",
          port: 1812,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "supersecret",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
          username: ''
        }
      )
        
      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"radiusprofile"=>[{"_id"=>BSON::ObjectId('2c7a318c38c5ce2f86d179cb'), "attr_no_delete"=>true, "attr_hidden_id"=>"Default", "name"=>"Default", "site_id"=>"3c7f226b2315be2087a1d5b2", "use_usg_auth_server"=>true, "auth_servers"=>[{"ip"=>"192.168.0.1", "port"=>1812, "x_secret"=>"supersecret"}], "acct_servers"=>[]}]}
      )
    end      
  end

  context 'handles ntp'  do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'servers from ubiquiti' do
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Ubiquiti Unifi'})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"ntp", "ntp_server_1"=>"0.ubnt.pool.ntp.org", "ntp_server_2"=>"1.ubnt.pool.ntp.org", "ntp_server_3"=>"2.ubnt.pool.ntp.org", "ntp_server_4"=>"3.ubnt.pool.ntp.org"}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )

      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"ntp", "ntp_server_1"=>"0.ubnt.pool.ntp.org", "ntp_server_2"=>"1.ubnt.pool.ntp.org", "ntp_server_3"=>"2.ubnt.pool.ntp.org", "ntp_server_4"=>"3.ubnt.pool.ntp.org"}]}
      )
    end

    it 'servers that are not default' do
      expect(aux_unifi).to receive(:print_good).with('NTP Server: 1.2.3.4')
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Ubiquiti Unifi'})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"ntp", "ntp_server_1"=>"1.2.3.4", "ntp_server_2"=>"", "ntp_server_3"=>"", "ntp_server_4"=>""}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )
      expect(aux_unifi).to receive(:report_service).with(
        {:host=>"1.2.3.4", :name=>"ntp", :port=>"123", :proto=>"udp"}
      )

      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"ntp", "ntp_server_1"=>"1.2.3.4", "ntp_server_2"=>"", "ntp_server_3"=>"", "ntp_server_4"=>""}]}
      )
    end
  end

  context 'handles ssh configurations' do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'with passwords' do
      expect(aux_unifi).to receive(:print_good).with('SSH user admin found with password 16xoB6F2UyAcU6fP and hash $6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V.')
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Ubiquiti Unifi'})
      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1337,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V.",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED,
          username: 'admin'
        }
      )
      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9bb'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"mgmt", "advanced_feature_enabled"=>false, "x_ssh_enabled"=>true, "x_ssh_bind_wildcard"=>false, "x_ssh_auth_password_enabled"=>true, "unifi_idp_enabled"=>true, "x_mgmt_key"=>"ba6cbe170f8276cd86b24ac79ab29afc", "x_ssh_username"=>"admin", "x_ssh_password"=>"16xoB6F2UyAcU6fP", "x_ssh_keys"=>[], "x_ssh_sha512passwd"=>"$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V."}]}
      )
    end

    it 'with keys' do
      expect(aux_unifi).to receive(:print_good).with('SSH user admin found with password 16xoB6F2UyAcU6fP and hash $6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V.')
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Ubiquiti Unifi'})
      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1337,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V.",
          private_type: :nonreplayable_hash,
          status: Metasploit::Model::Login::Status::UNTRIED,
          username: 'admin'
        }
      )
      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9bb'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"mgmt", "advanced_feature_enabled"=>false, "x_ssh_enabled"=>true, "x_ssh_bind_wildcard"=>false, "x_ssh_auth_password_enabled"=>false, "unifi_idp_enabled"=>true, "x_mgmt_key"=>"ba6cbe170f8276cd86b24ac79ab29afc", "x_ssh_username"=>"admin", "x_ssh_password"=>"16xoB6F2UyAcU6fP", "x_ssh_keys"=>['test to make this fail'], "x_ssh_sha512passwd"=>"$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V."}]}
      )
    end
  end

  context 'handles mesh' do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'handles mesh configurations' do
      expect(aux_unifi).to receive(:print_good).with('Mesh Wifi Network vwire-851237d214c8c6ba password 523a9b872b4624c7894f96c3ae22cdfa')
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :os_name => 'Ubiquiti Unifi'})
      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1337,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "523a9b872b4624c7894f96c3ae22cdfa",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
          username: 'vwire-851237d214c8c6ba'
        }
      )
      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9bc'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"connectivity", "enabled"=>true, "uplink_type"=>"gateway", "x_mesh_essid"=>"vwire-851237d214c8c6ba", "x_mesh_psk"=>"523a9b872b4624c7894f96c3ae22cdfa"}]}
      )
    end
  end
end
