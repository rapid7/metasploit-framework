# -*- coding: binary -*-

require 'metasploit/framework/hashes/identify'
require 'bson'
require 'zip'

module Msf
  ###
  #
  # This module provides methods for working with Ubiquiti equipment
  #
  ###
  module Auxiliary::Ubiquiti
    include Msf::Auxiliary::Report

    def decrypt_unf(contents)
      aes = OpenSSL::Cipher.new('aes-128-cbc')
      aes.decrypt
      aes.key = 'bcyangkmluohmars' # https://github.com/zhangyoufu/unifi-backup-decrypt/blob/master/E>
      aes.padding = 0
      aes.iv = 'ubntenterpriseap'
      aes.update(contents)
    end

    def repair_zip(fname)
      zip_exe = Msf::Util::Helper.which('zip')
      if zip_exe.nil?
        print_error('Zip utility not found.')
        return nil
      end
      print_status('Attempting to repair zip file (this is normal and takes some time)')
      temp_file = Rex::Quickfile.new('fixed_zip')
      system("yes | #{zip_exe} -FF #{fname} --out #{temp_file.path}.zip > /dev/null")
      return File.read("#{temp_file.path}.zip")
    end

    def extract_and_process_db(db_path)
      f = nil
      Zip::File.open(db_path) do |zip_file|
        # Handle entries one by one
        zip_file.each do |entry|
          # Extract to file
          next unless entry.name == 'db.gz'

          print_status('extracting db.gz')
          gz = Zlib::GzipReader.new(entry.get_input_stream)
          f = gz.read
          gz.close
          break
        end
      end
      f
    end

    def bson_to_json(byte_buffer)
      # This function takes a byte buffer (db file from Unifi read in), which is a bson string
      # it then converts it to JSON, where it uses the 'select collection' documents
      # as keys.  For instance a bson that contained the follow (displayed in json
      # for ease):
      # {"__cmd"=>"select", "collection"=>"heatmap"}
      # {'example'=>'example'}
      # {'example2'=>'example2'}
      # would become:
      # {'heatmap'=>[{'example'=>'example'}, {'example2'=>'example2'}]}
      # this is mainly done to ease the grouping of items for easy navigation later.

      buf = BSON::ByteBuffer.new(byte_buffer)
      output = {}
      key = ''

      while buf
        begin
          # read the document from the buffer
          bson = BSON::Document.from_bson(buf)
          if bson.has_key?('__cmd')
            key = bson['collection']
            output[key] = []
            next
          end
          output[key] << bson
        rescue RangeError
          break
        end
      end
      output
    end

    def unifi_config_eater(thost, tport, config)
      # This is for the Ubiquiti Unifi files.  These are typically in the backup download zip file
      # then in the db.gz file as db.  It is a MongoDB BSON file, which can be difficult to read.
      # https://stackoverflow.com/questions/51242412/undefined-method-read-bson-document-for-bsonmodule
      # The BSON file is a bunch of BSON Documents chained together.  There doesn't seem to be a good
      # way to read these files directly, so looping through loading the content seems to work with
      # minimal repercussions.

      # The file format is broken into sections by __cmd select documents as such:
      # {"__cmd"=>"select", "collection"=>"heatmap"}
      # we can pull the relevant section name via the collection value.

      if framework.db.active
        creds_template = {
          address: thost,
          port: tport,
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          origin_type: :service,
          private_type: :password,
          service_name: '',
          module_fullname: fullname,
          status: Metasploit::Model::Login::Status::UNTRIED
        }
      end

      report_host({
        host: thost,
        info: 'Ubiquiti Unifi Controller'
      })

      store_loot('unifi.json', 'application/json', thost, config.to_s.strip, 'unifi.json', 'Ubiquiti Unifi Configuration')

      # Example BSON lines
      # {"__cmd"=>"select", "collection"=>"admin"}
      # {"_id"=>BSON::ObjectId('5c7f23af3825ce2067a1d9ce'), "name"=>"adminuser", "email"=>"admin@admin.com", "x_shadow"=>"$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V.", "time_created"=>1551825823, "last_site_name"=>"default", "ubic_name"=>"admin@admin.com", "ubic_uuid"=>"c23da064-3f4d-282f-1dc9-7e25f9c6812c", "ui_settings"=>{"dashboardConfig"=>{"lastActiveDashboardId"=>"2c7f2d213813ce2487d1ac38", "dashboards"=>{"3c7f678a3815ce2021d1d9c7"=>{"order"=>1}, "5b4f2d269115ce2087d1abb9"=>{}}}}}
      def process_admin(lines, credential_data)
        lines.each do |line|
          admin_name = line['name']
          admin_email = line['email']
          admin_password_hash = line['x_shadow']
          print_good("Admin user #{admin_name} with email #{admin_email} found with password hash #{admin_password_hash}")
          next unless framework.db.active

          cred = credential_data.dup
          cred[:username] = admin_name
          cred[:private_data] = admin_password_hash
          cred[:private_type] = :nonreplayable_hash
          create_credential_and_login(cred)
        end
      end

      # Example BSON lines
      # {"__cmd"=>"select", "collection"=>"firewallrule"}
      # {"_id"=>BSON::ObjectId('5c7f23af3825ce2067a1d9ce'), "ruleset" => "WAN_OUT", "rule_index" => "2000", "name" => "Block Example", "enabled" => true, "action" => "reject", "protocol_match_excepted" => false, "logging" => false, "state_new" => false, "state_established" => false, "state_invalid" => false, "state_related" => false, "ipsec" => "", "src_firewallgroup_ids" => ["1a1c15a11111ce14b1f1111a"], "src_mac_address" => "", "dst_firewallgroup_ids" => [], "dst_address" => "", "src_address" => "", "protocol" => "all", "icmp_typename" => "", "src_networkconf_id" => "", "src_networkconf_type" => "NETv4", "dst_networkconf_id" => "", "dst_networkconf_type" => "NETv4", "site_id" => "1c1f208b3815ce1111a1a1a1"}
      def process_firewallrule(lines, _)
        lines.each do |line|
          rule = (line['action']).to_s
          unless line['dst_address'].empty?
            rule << " dst addresses: #{line['dst_address']}"
          end
          unless line['dst_firewallgroup_ids'].empty?
            rule << " dst group: #{line['dst_firewallgroup_ids'].join(', ')}"
          end
          unless line['src_address'].empty?
            rule << " src addresses: #{line['src_address']}"
          end
          unless line['src_firewallgroup_ids'].empty?
            rule << " src group: #{line['src_firewallgroup_ids'].join(', ')}"
          end
          rule << " protocol: #{line['protocol']}"

          print_status("#{line['enabled'] ? 'Enabled' : 'Disabled'} Firewall Rule '#{line['name']}': #{rule}")
        end
      end

      # Example BSON lines
      # {"__cmd"=>"select", "collection"=>"radiusprofile"}
      # {"_id"=>BSON::ObjectId('2c7a318c38c5ce2f86d179cb'), "attr_no_delete"=>true, "attr_hidden_id"=>"Default", "name"=>"Default", "site_id"=>"3c7f226b2315be2087a1d5b2", "use_usg_auth_server"=>true, "auth_servers"=>[{"ip"=>"192.168.0.1", "port"=>1812, "x_secret"=>""}], "acct_servers"=>[]}
      def process_radiusprofile(lines, credential_data)
        lines.each do |line|
          line['auth_servers'].each do |server|
            report_service(
              host: server['ip'],
              port: server['port'],
              name: 'radius',
              proto: 'udp'
            )
            next unless server['x_secret'] # no need to output if the secret is blank, therefore its not configured

            print_good("Radius server: #{server['ip']}:#{server['port']} with secret '#{server['x_secret']}'")
            next unless framework.db.active

            cred = credential_data.dup
            cred[:username] = ''
            cred[:private_data] = server['x_secret']
            cred[:address] = server['ip']
            cred[:port] = server['port']
            create_credential_and_login(cred)
          end
        end
      end

      # settings has multiple items we care about:
      #   x_mesh_essid/x_mesh_psk -> should contain the mesh network wifi name and password
      #   ntp -> ntp servers
      #   x_ssh_username/x_ssh_password/x_ssh_keys/x_ssh_sha512passwd

      # Example lines
      # {"__cmd"=>"select", "collection"=>"setting"}
      # {"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"ntp", "ntp_server_1"=>"0.ubnt.pool.ntp.org", "ntp_server_2"=>"1.ubnt.pool.ntp.org", "ntp_server_3"=>"2.ubnt.pool.ntp.org", "ntp_server_4"=>"3.ubnt.pool.ntp.org"}
      # {"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9bb'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"mgmt", "advanced_feature_enabled"=>false, "x_ssh_enabled"=>true, "x_ssh_bind_wildcard"=>false, "x_ssh_auth_password_enabled"=>true, "unifi_idp_enabled"=>true, "x_mgmt_key"=>"ba6cbe170f8276cd86b24ac79ab29afc", "x_ssh_username"=>"admin", "x_ssh_password"=>"16xoB6F2UyAcU6fP", "x_ssh_keys"=>[], "x_ssh_sha512passwd"=>"$6$R4qnAaaF$AAAlL2t.fXu0aaa9z3uvcIm3ujbtJLhIO.lN1xZqHZPQoUAXs2BUTmI5UbuBo2/8t3epzbVLib17Ls7GCVx7V."}
      # {"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9bc'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"connectivity", "enabled"=>true, "uplink_type"=>"gateway", "x_mesh_essid"=>"vwire-851237d214c8c6ba", "x_mesh_psk"=>"523a9b872b4624c7894f96c3ae22cdfa"}
      # {"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9bd'), "site_id"=>"3c2f215b3825ca2087c1dfb6", "key"=>"snmp", "community": "public", "enabled": true, "enabledV3": true, "username": "usernamesnmpv3", "x_password": "passwordsnmpv3"}
      def process_setting(lines, credential_data)
        lines.each do |line|
          case line['key']
          when 'snmp'
            if framework.db.active
              cred = credential_data.dup
              cred[:protocol] = 'udp'
              cred[:port] = 161
              cred[:service_name] = 'snmp'
            else
              cred = {} # throw away
            end
            unless line['community'].blank?
              print_good("SNMP v2 #{line['enabled'] ? 'enabled' : 'disabled'} with password #{line['community']}")
              cred[:private_data] = line['community']
              create_credential_and_login(cred) if framework.db.active
            end
            unless line['x_password'].blank? || line['username'].blank?
              print_good("SNMP v3 #{line['enabledV3'] ? 'enabled' : 'disabled'} with username #{line['username']} password #{line['x_password']}")
              cred[:username] = line['username']
              cred[:private_data] = line['x_password']
              create_credential_and_login(cred) if framework.db.active
            end
          when 'connectivity'
            print_good("Mesh Wifi Network #{line['x_mesh_essid']} password #{line['x_mesh_psk']}")
            next unless framework.db.active

            cred = credential_data.dup
            cred[:username] = line['x_mesh_essid']
            cred[:private_data] = line['x_mesh_psk']
            create_credential_and_login(cred)
          when 'ntp'
            ['ntp_server_1', 'ntp_server_2', 'ntp_server_3', 'ntp_server_4'].each do |ntp|
              next if line[ntp].empty? || line[ntp].ends_with?('ubnt.pool.ntp.org')

              report_service(
                host: line[ntp],
                port: '123',
                name: 'ntp',
                proto: 'udp'
              )
              print_good("NTP Server: #{line[ntp]}")
            end
          when 'mgmt'
            admin_name = line['x_ssh_username']
            admin_password_hash = line['x_ssh_sha512passwd']
            admin_password = line['x_ssh_password']
            print_good("SSH user #{admin_name} found with password #{admin_password} and hash #{admin_password_hash}")
            line['x_ssh_keys'].each do |key|
              print_good("SSH user #{admin_name} found with SSH key: #{key}")
            end
            next unless framework.db.active

            cred = credential_data.dup
            cred[:username] = admin_name
            cred[:private_data] = admin_password_hash
            cred[:private_type] = :nonreplayable_hash
            login = create_credential_and_login(cred)
            if login.present? && admin_password.present?
              create_cracked_credential(username: admin_name, password: admin_password, core_id: login.core.id)
            end
          end
        end
      end

      # Example lines
      # {"__cmd"=>"select", "collection"=>"wlanconf"}
      # {"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "enabled" => true, "security" => "wpapsk", "wep_idx" => 1, "wpa_mode" => "wpa2", "wpa_enc" => "ccmp", "usergroup_id" => "5a7f111a3815ce1111a1d1c3", "dtim_mode" => "default", "dtim_ng" => 1, "dtim_na" => 1, "minrate_ng_enabled" => false, "minrate_ng_advertising_rates" => false, "minrate_ng_data_rate_kbps" => 1000, "minrate_ng_cck_rates_enabled" => true, "minrate_na_enabled" => false, "minrate_na_advertising_rates" => false, "minrate_na_data_rate_kbps" => 6000, "mac_filter_enabled" => false, "mac_filter_policy" => "allow", "mac_filter_list" => [], "bc_filter_enabled" => false, "bc_filter_list" => [], "group_rekey" => 3600, "name" => "ssid_name", "x_passphrase" => "supersecret", "wlangroup_id" => "5c7f208c3815ce2087d1d9c4", "schedule" => [], "minrate_ng_mgmt_rate_kbps" => 1000, "minrate_na_mgmt_rate_kbps" => 6000, "minrate_ng_beacon_rate_kbps" => 1000, "minrate_na_beacon_rate_kbps" => 6000, "site_id" => "5c7f208b3815ce2087d1d9b6", "x_iapp_key" => "d11a1c86df1111be86aaa69e8aa1c57f", "no2ghz_oui" => true}
      def process_wlanconf(lines, credential_data)
        lines.each do |line|
          ssid = line['name']
          mode = line['security']
          password = line['x_passphrase']
          print_good("#{line['enabled'] ? 'Enabled' : 'Disabled'} wifi #{ssid} on #{mode}(#{line['wpa_mode']},#{line['wpa_enc']}) has password #{password}")
          next unless framework.db.active

          cred = credential_data.dup
          cred[:username] = ssid
          cred[:private_data] = password
          create_credential_and_login(cred)
        end
      end

      # Example lines
      # {"__cmd"=>"select", "collection"=>"firewallgroup"}
      # {"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "name" => "Cameras", "group_type" => "address-group", "group_members" => ["1.1.1.1"], "site_id" => "5c7f111b3815ce208aaa111a"}
      def process_firewallgroup(lines, _)
        lines.each do |line|
          print_status("Firewall Group: #{line['name']}, group type: #{line['group_type']}, members: #{line['group_members'].join(', ')}")
        end
      end

      # Example lines
      # {"__cmd"=>"select", "collection"=>"device"}
      # {"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "ip" => "5.5.5.5", "mac" => "cc:cc:cc:cc:cc:cc", "model" => "UGW3", "type" => "ugw", "version" => "4.4.44.5213844", "adopted" => true, "site_id" => "5aaaaaabaaaaae1117d1d1b6", "x_authkey" => "eaaaaaaa63e59ab89c111e11d6e11aa1", "cfgversion" => "aaa4b11b1df1a111", "config_network" => {"type" => "dhcp", "ip" => "1.1.1.1"}, "license_state" => "registered", "two_phase_adopt" => false, "unsupported" => false, "unsupported_reason" => 0, "x_fingerprint" => "aa:aa:11:aa:11:11:11:11:11:11:11:11:11:11:11:11", "x_ssh_hostkey" => "MIIBIjANBgkAhkiG9w0AAQEFAAOCAQ8AMIIBCgKCAQEAAU4S/7r548xvtGuHlgAAAKzkrL+t97ZWAZru8wQFbltEB4111HiIAkzt041td8V+P7c1bQtn3YQdViAuH2h2sgt8feAvMWo56OskAoDvHwAEv5AWqmPKy/xmKbdfgA5wTzvSztPGFA4QuOuA1YxQICf1MgpoOtplAAA31JxAYF/t7n8qgvJlm1JRv2AAAZHHtSiz1IaxzOO9LAAAqCfHvHugPcZYk2yAAAP7JrnnR1fAVj9F4aaYaA0eSjvDTAglykXHCbh1EWAAAecqHZ/SWn9cjmuAAArZxxG6m6Eu/aj9we82/PmtKzQGN0RWUsgrxajQowtNpVsNTnaOglUsfQIDAAAA", "x_ssh_hostkey_fingerprint" => "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11", "inform_url" => "http://1.1.2.2:8080/inform", "inform_ip" => "1.1.1.1", "serial" => "AAAAAAAAAAAA", "required_version" => "4.0.0", "ethernet_table" => [{ "mac" => "b4:fb:e4:cc:cc:cc", "num_port" => 1, "name" => "eth0"}, {"mac" => "b4:fb:e4:bb:bb:bb", "num_port" => 1, "name" => "eth1"}, {"mac" => "b4:fb:e4:aa:aa:aa", "num_port" => 1, "name" => "eth2"}], "fw_caps" => 184323, "hw_caps" => 0, "usg_caps" => 786431, "board_rev" => 16, "x_aes_gcm" => true, "ethernet_overrides" => [{"ifname" => "eth1", "networkgroup" => "LAN"}, {"ifname" => "eth0", "networkgroup" => "WAN"}], "led_override" => "default", "led_override_color" => "#0000ff", "led_override_color_brightness" => 100, "outdoor_mode_override" => "default", "name" => "USG", "map_id" => "1a111c2e1111ce2087d1e199", "x" => -22.11111198630405, "y" => -41.1111113859866, "heightInMeters" => 2.4}
      def process_device(lines, _)
        lines.each do |line|
          report_host({
            host: line['ip'],
            name: line['name'],
            mac: line['mac'],
            os_name: 'Ubiquiti Unifi'
          })
          print_good("Unifi Device #{line['name']} of model #{line['model']} on #{line['ip']}")
        end
      end

      # Example lines
      # {"__cmd"=>"select", "collection"=>"user"}
      # {"_id"=>BSON::ObjectId('3c3e21ac3715ce20a721d9ba'), "mac" => "00:0c:29:11:aa:11", "site_id" => "5c7f111b1111aa2087d11111", "oui" => "Vmware", "is_guest" => false, "first_seen" => 1551111161, "last_seen" => 1561621747, "is_wired" => true, "hostname" => "android", "usergroup_id" => "", "name" => "example device", "noted" => true, "use_fixedip" =>  true, "network_id" => "1c7f111a1115aa2087aaa9aa", "fixed_ip" => "7.7.7.7"}
      def process_user(lines, _)
        lines.each do |line|
          host_hash = {
            name: line['hostname'],
            mac: line['mac']
          }
          desc = "#{line['hostname']} (#{line['mac']})"
          if line['fixed_ip']
            host_hash[:host] = line['fixed_ip']
            desc << " on IP #{line['fixed_ip']}"
          end
          if line['name']
            host_hash[:info] = line['name']
            desc << " with name #{line['name']}"
          end
          report_host(host_hash)
          print_good("Network Device #{desc} found")
        end
      end

      # here is where we actually process the file
      config.each do |key, value|
        next unless respond_to?("process_#{key}")

        credential_data = creds_template.dup
        send("process_#{key}", value, credential_data)
      end
    end
  end
end
