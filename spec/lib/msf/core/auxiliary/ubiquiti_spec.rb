# -*- coding: binary -*-
require 'spec_helper'

require 'bson'

RSpec.describe Msf::Auxiliary::Ubiquiti do
  class DummyUnifiClass
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
    def print_status(str=nil)
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

  subject(:aux_unifi) { DummyUnifiClass.new }

  let!(:workspace) { FactoryBot.create(:mdm_workspace) }

  context '#create_credential_and_login' do

    let(:session) { FactoryBot.create(:mdm_session) }

    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace)}

    let(:user) { FactoryBot.create(:mdm_user)}

    subject(:test_object) { DummyUnifiClass.new }
    
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
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
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
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
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

  context 'handles firewall' do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'rules printing' do
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:print_status).with("Enabled Firewall Rule 'Block Example': reject src group: 1a1c15a11111ce14b1f1111a protocol: all")
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"firewallrule"=>[{"_id"=>BSON::ObjectId('5c7f23af3825ce2067a1d9ce'), "ruleset" => "WAN_OUT", "rule_index" => "2000", "name" => "Block Example", "enabled" => true, "action" => "reject", "protocol_match_excepted" => false, "logging" => false, "state_new" => false, "state_established" => false, "state_invalid" => false, "state_related" => false, "ipsec" => "", "src_firewallgroup_ids" => ["1a1c15a11111ce14b1f1111a"], "src_mac_address" => "", "dst_firewallgroup_ids" => [], "dst_address" => "", "src_address" => "", "protocol" => "all", "icmp_typename" => "", "src_networkconf_id" => "", "src_networkconf_type" => "NETv4", "dst_networkconf_id" => "", "dst_networkconf_type" => "NETv4", "site_id" => "1c1f208b3815ce1111a1a1a1"}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )

      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"firewallrule"=>[{"_id"=>BSON::ObjectId('5c7f23af3825ce2067a1d9ce'), "ruleset" => "WAN_OUT", "rule_index" => "2000", "name" => "Block Example", "enabled" => true, "action" => "reject", "protocol_match_excepted" => false, "logging" => false, "state_new" => false, "state_established" => false, "state_invalid" => false, "state_related" => false, "ipsec" => "", "src_firewallgroup_ids" => ["1a1c15a11111ce14b1f1111a"], "src_mac_address" => "", "dst_firewallgroup_ids" => [], "dst_address" => "", "src_address" => "", "protocol" => "all", "icmp_typename" => "", "src_networkconf_id" => "", "src_networkconf_type" => "NETv4", "dst_networkconf_id" => "", "dst_networkconf_type" => "NETv4", "site_id" => "1c1f208b3815ce1111a1a1a1"}]}
      )
    end
  end

  context 'handles snmp' do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'v2 enabled' do
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:print_good).with('SNMP v2 enabled with password public')
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "key" => "snmp", "site_id" => "1a2f208b9999ce2087a7b9c2", "community" => "public", "enabled" => true, "enabledV3" => false, "username" => "", "x_password" => ""}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )

      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "public",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "key" => "snmp", "site_id" => "1a2f208b9999ce2087a7b9c2", "community" => "public", "enabled" => true, "enabledV3" => false, "username" => "", "x_password" => ""}]}
      )
    end

    it 'v2 disabled' do
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:print_good).with('SNMP v2 disabled with password public')
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "key" => "snmp", "site_id" => "1a2f208b9999ce2087a7b9c2", "community" => "public", "enabled" => false, "enabledV3" => false, "username" => "", "x_password" => ""}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )

      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "public",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
        }
      )
      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "key" => "snmp", "site_id" => "1a2f208b9999ce2087a7b9c2", "community" => "public", "enabled" => false, "enabledV3" => false, "username" => "", "x_password" => ""}]}
      )
    end

    it 'v3 enabled' do
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:print_good).with('SNMP v3 enabled with username usernamesnmpv3 password passwordsnmpv3')
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "key" => "snmp", "site_id" => "1a2f208b9999ce2087a7b9c2", "community" => "", "enabled" => false, "enabledV3" => true, "username" => "usernamesnmpv3", "x_password" => "passwordsnmpv3"}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )

      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "passwordsnmpv3",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
          username: 'usernamesnmpv3'
        }
      )
      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "key" => "snmp", "site_id" => "1a2f208b9999ce2087a7b9c2", "community" => "", "enabled" => false, "enabledV3" => true, "username" => "usernamesnmpv3", "x_password" => "passwordsnmpv3"}]}
      )
    end

    it 'v3 disabled' do
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:print_good).with('SNMP v3 disabled with username usernamesnmpv3 password passwordsnmpv3')
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "key" => "snmp", "site_id" => "1a2f208b9999ce2087a7b9c2", "community" => "", "enabled" => false, "enabledV3" => false, "username" => "usernamesnmpv3", "x_password" => "passwordsnmpv3"}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )

      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 161,
          protocol: "udp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: 'snmp',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "passwordsnmpv3",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
          username: 'usernamesnmpv3'
        }
      )
      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "key" => "snmp", "site_id" => "1a2f208b9999ce2087a7b9c2", "community" => "", "enabled" => false, "enabledV3" => false, "username" => "usernamesnmpv3", "x_password" => "passwordsnmpv3"}]}
      )
    end
  end

  context 'handles ntp'  do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'servers from ubiquiti' do
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
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
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
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
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9bb'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"mgmt", "advanced_feature_enabled"=>false, "x_ssh_enabled"=>true, "x_ssh_bind_wildcard"=>false, "x_ssh_auth_password_enabled"=>true, "unifi_idp_enabled"=>true, "x_mgmt_key"=>"ba6cbe170f8276cd86b24ac79ab29afc", "x_ssh_username"=>"admin", "x_ssh_password"=>"16xoB6F2UyAcU6fP", "x_ssh_keys"=>[], "x_ssh_sha512passwd"=>"$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V."}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )
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
      expect(aux_unifi).to receive(:print_good).with('SSH user admin found with SSH key: test to make this fail')
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9bb'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"mgmt", "advanced_feature_enabled"=>false, "x_ssh_enabled"=>true, "x_ssh_bind_wildcard"=>false, "x_ssh_auth_password_enabled"=>false, "unifi_idp_enabled"=>true, "x_mgmt_key"=>"ba6cbe170f8276cd86b24ac79ab29afc", "x_ssh_username"=>"admin", "x_ssh_password"=>"16xoB6F2UyAcU6fP", "x_ssh_keys"=>['test to make this fail'], "x_ssh_sha512passwd"=>"$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V."}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )
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
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {"setting"=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9bc'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"connectivity", "enabled"=>true, "uplink_type"=>"gateway", "x_mesh_essid"=>"vwire-851237d214c8c6ba", "x_mesh_psk"=>"523a9b872b4624c7894f96c3ae22cdfa"}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )
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

  context 'handles wifi' do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'with wpa2' do
      expect(aux_unifi).to receive(:print_good).with('Enabled wifi ssid_name on wpapsk(wpa2,ccmp) has password supersecret')
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {'wlanconf'=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "enabled" => true, "security" => "wpapsk", "wep_idx" => 1, "wpa_mode" => "wpa2", "wpa_enc" => "ccmp", "usergroup_id" => "5a7f111a3815ce1111a1d1c3", "dtim_mode" => "default", "dtim_ng" => 1, "dtim_na" => 1, "minrate_ng_enabled" => false, "minrate_ng_advertising_rates" => false, "minrate_ng_data_rate_kbps" => 1000, "minrate_ng_cck_rates_enabled" => true, "minrate_na_enabled" => false, "minrate_na_advertising_rates" => false, "minrate_na_data_rate_kbps" => 6000, "mac_filter_enabled" => false, "mac_filter_policy" => "allow", "mac_filter_list" => [], "bc_filter_enabled" => false, "bc_filter_list" => [], "group_rekey" => 3600, "name" => "ssid_name", "x_passphrase" => "supersecret", "wlangroup_id" => "5c7f208c3815ce2087d1d9c4", "schedule" => [], "minrate_ng_mgmt_rate_kbps" => 1000, "minrate_na_mgmt_rate_kbps" => 6000, "minrate_ng_beacon_rate_kbps" => 1000, "minrate_na_beacon_rate_kbps" => 6000, "site_id" => "5c7f208b3815ce2087d1d9b6", "x_iapp_key" => "d11a1c86df1111be86aaa69e8aa1c57f", "no2ghz_oui" => true}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )
      expect(aux_unifi).to receive(:create_credential_and_login).with(
        {
          address: "127.0.0.1",
          port: 1337,
          protocol: "tcp",
          workspace_id: workspace.id,
          origin_type: :service,
          service_name: '',
          module_fullname: "auxiliary/scanner/snmp/ubiquiti_dummy",
          private_data: "supersecret",
          private_type: :password,
          status: Metasploit::Model::Login::Status::UNTRIED,
          username: 'ssid_name'
        }
      )
      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {'wlanconf'=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "enabled" => true, "security" => "wpapsk", "wep_idx" => 1, "wpa_mode" => "wpa2", "wpa_enc" => "ccmp", "usergroup_id" => "5a7f111a3815ce1111a1d1c3", "dtim_mode" => "default", "dtim_ng" => 1, "dtim_na" => 1, "minrate_ng_enabled" => false, "minrate_ng_advertising_rates" => false, "minrate_ng_data_rate_kbps" => 1000, "minrate_ng_cck_rates_enabled" => true, "minrate_na_enabled" => false, "minrate_na_advertising_rates" => false, "minrate_na_data_rate_kbps" => 6000, "mac_filter_enabled" => false, "mac_filter_policy" => "allow", "mac_filter_list" => [], "bc_filter_enabled" => false, "bc_filter_list" => [], "group_rekey" => 3600, "name" => "ssid_name", "x_passphrase" => "supersecret", "wlangroup_id" => "5c7f208c3815ce2087d1d9c4", "schedule" => [], "minrate_ng_mgmt_rate_kbps" => 1000, "minrate_na_mgmt_rate_kbps" => 6000, "minrate_ng_beacon_rate_kbps" => 1000, "minrate_na_beacon_rate_kbps" => 6000, "site_id" => "5c7f208b3815ce2087d1d9b6", "x_iapp_key" => "d11a1c86df1111be86aaa69e8aa1c57f", "no2ghz_oui" => true}]}
      )
    end
  end

  context 'handles firewallgroups' do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'prints correctly' do
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:print_status).with('Firewall Group: Cameras, group type: address-group, members: 1.1.1.1')
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {'firewallgroup'=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "name" => "Cameras", "group_type" => "address-group", "group_members" => ["1.1.1.1"], "site_id" => "5c7f111b3815ce208aaa111a"}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )

      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {'firewallgroup'=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "name" => "Cameras", "group_type" => "address-group", "group_members" => ["1.1.1.1"], "site_id" => "5c7f111b3815ce208aaa111a"}]}
      )
    end
  end

  context 'handles devices' do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'report_host correctly' do
      expect(aux_unifi).to receive(:print_good).with('Unifi Device USG of model UGW3 on 5.5.5.5')
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:report_host).with({:host => '5.5.5.5', :os_name => 'Ubiquiti Unifi', :mac=>"cc:cc:cc:cc:cc:cc", :name=>"USG"})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {'device'=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "ip" => "5.5.5.5", "mac" => "cc:cc:cc:cc:cc:cc", "model" => "UGW3", "type" => "ugw", "version" => "4.4.44.5213844", "adopted" => true, "site_id" => "5aaaaaabaaaaae1117d1d1b6", "x_authkey" => "eaaaaaaa63e59ab89c111e11d6e11aa1", "cfgversion" => "aaa4b11b1df1a111", "config_network" => {"type" => "dhcp", "ip" => "1.1.1.1"}, "license_state" => "registered", "two_phase_adopt" => false, "unsupported" => false, "unsupported_reason" => 0, "x_fingerprint" => "aa:aa:11:aa:11:11:11:11:11:11:11:11:11:11:11:11", "x_ssh_hostkey" => "MIIBIjANBgkAhkiG9w0AAQEFAAOCAQ8AMIIBCgKCAQEAAU4S/7r548xvtGuHlgAAAKzkrL+t97ZWAZru8wQFbltEB4111HiIAkzt041td8V+P7c1bQtn3YQdViAuH2h2sgt8feAvMWo56OskAoDvHwAEv5AWqmPKy/xmKbdfgA5wTzvSztPGFA4QuOuA1YxQICf1MgpoOtplAAA31JxAYF/t7n8qgvJlm1JRv2AAAZHHtSiz1IaxzOO9LAAAqCfHvHugPcZYk2yAAAP7JrnnR1fAVj9F4aaYaA0eSjvDTAglykXHCbh1EWAAAecqHZ/SWn9cjmuAAArZxxG6m6Eu/aj9we82/PmtKzQGN0RWUsgrxajQowtNpVsNTnaOglUsfQIDAAAA", "x_ssh_hostkey_fingerprint" => "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11", "inform_url" => "http://1.1.2.2:8080/inform", "inform_ip" => "1.1.1.1", "serial" => "AAAAAAAAAAAA", "required_version" => "4.0.0", "ethernet_table" => [{ "mac" => "b4:fb:e4:cc:cc:cc", "num_port" => 1, "name" => "eth0"}, {"mac" => "b4:fb:e4:bb:bb:bb", "num_port" => 1, "name" => "eth1"}, {"mac" => "b4:fb:e4:aa:aa:aa", "num_port" => 1, "name" => "eth2"}], "fw_caps" => 184323, "hw_caps" => 0, "usg_caps" => 786431, "board_rev" => 16, "x_aes_gcm" => true, "ethernet_overrides" => [{"ifname" => "eth1", "networkgroup" => "LAN"}, {"ifname" => "eth0", "networkgroup" => "WAN"}], "led_override" => "default", "led_override_color" => "#0000ff", "led_override_color_brightness" => 100, "outdoor_mode_override" => "default", "name" => "USG", "map_id" => "1a111c2e1111ce2087d1e199", "x" => -22.11111198630405, "y" => -41.1111113859866, "heightInMeters" => 2.4}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )

      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {'device'=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "ip" => "5.5.5.5", "mac" => "cc:cc:cc:cc:cc:cc", "model" => "UGW3", "type" => "ugw", "version" => "4.4.44.5213844", "adopted" => true, "site_id" => "5aaaaaabaaaaae1117d1d1b6", "x_authkey" => "eaaaaaaa63e59ab89c111e11d6e11aa1", "cfgversion" => "aaa4b11b1df1a111", "config_network" => {"type" => "dhcp", "ip" => "1.1.1.1"}, "license_state" => "registered", "two_phase_adopt" => false, "unsupported" => false, "unsupported_reason" => 0, "x_fingerprint" => "aa:aa:11:aa:11:11:11:11:11:11:11:11:11:11:11:11", "x_ssh_hostkey" => "MIIBIjANBgkAhkiG9w0AAQEFAAOCAQ8AMIIBCgKCAQEAAU4S/7r548xvtGuHlgAAAKzkrL+t97ZWAZru8wQFbltEB4111HiIAkzt041td8V+P7c1bQtn3YQdViAuH2h2sgt8feAvMWo56OskAoDvHwAEv5AWqmPKy/xmKbdfgA5wTzvSztPGFA4QuOuA1YxQICf1MgpoOtplAAA31JxAYF/t7n8qgvJlm1JRv2AAAZHHtSiz1IaxzOO9LAAAqCfHvHugPcZYk2yAAAP7JrnnR1fAVj9F4aaYaA0eSjvDTAglykXHCbh1EWAAAecqHZ/SWn9cjmuAAArZxxG6m6Eu/aj9we82/PmtKzQGN0RWUsgrxajQowtNpVsNTnaOglUsfQIDAAAA", "x_ssh_hostkey_fingerprint" => "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11", "inform_url" => "http://1.1.2.2:8080/inform", "inform_ip" => "1.1.1.1", "serial" => "AAAAAAAAAAAA", "required_version" => "4.0.0", "ethernet_table" => [{ "mac" => "b4:fb:e4:cc:cc:cc", "num_port" => 1, "name" => "eth0"}, {"mac" => "b4:fb:e4:bb:bb:bb", "num_port" => 1, "name" => "eth1"}, {"mac" => "b4:fb:e4:aa:aa:aa", "num_port" => 1, "name" => "eth2"}], "fw_caps" => 184323, "hw_caps" => 0, "usg_caps" => 786431, "board_rev" => 16, "x_aes_gcm" => true, "ethernet_overrides" => [{"ifname" => "eth1", "networkgroup" => "LAN"}, {"ifname" => "eth0", "networkgroup" => "WAN"}], "led_override" => "default", "led_override_color" => "#0000ff", "led_override_color_brightness" => 100, "outdoor_mode_override" => "default", "name" => "USG", "map_id" => "1a111c2e1111ce2087d1e199", "x" => -22.11111198630405, "y" => -41.1111113859866, "heightInMeters" => 2.4}]}
      )
    end

  end

  context 'handles user devices' do
    before(:example) do
      expect(aux_unifi).to receive(:myworkspace).at_least(:once).and_return(workspace)
    end

    it 'report_host correctly' do
      expect(aux_unifi).to receive(:print_good).with('Network Device android (00:0c:29:11:aa:11) on IP 7.7.7.7 with name example device found')
      expect(aux_unifi).to receive(:report_host).with({:host => '127.0.0.1', :info => 'Ubiquiti Unifi Controller'})
      expect(aux_unifi).to receive(:report_host).with({:host => '7.7.7.7', :info => 'example device', :mac => "00:0c:29:11:aa:11", :name => "android"})
      expect(aux_unifi).to receive(:store_loot).with(
        "unifi.json", "application/json", "127.0.0.1",
        {'user'=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "mac" => "00:0c:29:11:aa:11", "site_id" => "5c7f111b1111aa2087d11111", "oui" => "Vmware", "is_guest" => false, "first_seen" => 1551111161, "last_seen" => 1561621747, "is_wired" => true, "hostname" => "android", "usergroup_id" => "", "name" => "example device", "noted" => true, "use_fixedip" =>  true, "network_id" => "1c7f111a1115aa2087aaa9aa", "fixed_ip" => "7.7.7.7"}]}.to_s,
        "unifi.json", "Ubiquiti Unifi Configuration"
      )

      aux_unifi.unifi_config_eater('127.0.0.1',1337,
        {'user'=>[{"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "mac" => "00:0c:29:11:aa:11", "site_id" => "5c7f111b1111aa2087d11111", "oui" => "Vmware", "is_guest" => false, "first_seen" => 1551111161, "last_seen" => 1561621747, "is_wired" => true, "hostname" => "android", "usergroup_id" => "", "name" => "example device", "noted" => true, "use_fixedip" =>  true, "network_id" => "1c7f111a1115aa2087aaa9aa", "fixed_ip" => "7.7.7.7"}]}
      )
    end
  end

end
