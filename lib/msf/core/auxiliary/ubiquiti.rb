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
    aes.key = 'bcyangkmluohmars' # https://github.com/zhangyoufu/unifi-backup-decrypt/blob/master/E>
    aes.padding = 0
    aes.decrypt
    aes.iv = 'ubntenterpriseap'
    aes.update(contents)
  end

  def repair_zip(fname)
    zip_exe = Msf::Util::Helper.which('zip')
    if zip_exe.nil?
      return nil
    end
    print_status('Attempting to repair zip file (this is normal and takes some time)')
    temp_file = Rex::Quickfile.new("fixed_zip")
    system("yes | #{zip_exe} -FF #{fname} --out #{temp_file.path}.zip > /dev/null")
    if $? == 0
      return File.read("#{temp_file.path}.zip")
    else
      print_error('Error fixing zip.  Attempt manually.')
      nil
    end
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

    credential_data = {
      address: thost,
      port: tport,
      protocol: 'tcp',
      workspace_id: myworkspace.id,
      origin_type: :service,
      service_name: '',
      module_fullname: self.fullname,
      status: Metasploit::Model::Login::Status::UNTRIED
    }

    report_host({
      :host => thost,
      :os_name => 'Ubiquiti Unifi'
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
        cred = credential_data.dup
        cred[:username] = admin_name
        cred[:private_data] = admin_password_hash
        cred[:private_type] = :nonreplayable_hash
        create_credential_and_login(cred)
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
          if server['x_secret'] # no need to output if the secret is blank, therefore its not configured
            print_good("Radius server: #{server['ip']}:#{server['port']} with secret '#{server['x_secret']}'")
            cred = credential_data.dup
            cred[:username] = ''
            cred[:private_data] = server['x_secret']
            cred[:private_type] = :password
            cred[:address] = server['ip']
            cred[:port] = server['port']
            create_credential_and_login(cred)
          end
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
    def process_settings(lines, credential_data)
      lines.each do |line|
        case line['key']
        when 'connectivity'
          cred = credential_data.dup
          cred[:username] = line['x_mesh_essid']
          cred[:private_data] = line['x_mesh_psk']
          cred[:private_type] = :password
          create_credential_and_login(cred)
          print_good("Mesh Wifi Network #{line['x_mesh_essid']} password #{line['x_mesh_psk']}")
        when 'ntp'
          ['ntp_server_1', 'ntp_server_2', 'ntp_server_3', 'ntp_server_4'].each do |ntp|
            unless line[ntp].empty? || line[ntp].ends_with?('ubnt.pool.ntp.org')
              report_service(
                host: line[ntp],
                port: '123',
                name: 'ntp',
                proto: 'udp'
              )
              print_good("NTP Server: #{line[ntp]}")
            end
          end
        when 'mgmt'
          admin_name = line['x_ssh_username']
          admin_password_hash = line['x_ssh_sha512passwd']
          admin_password = line['x_ssh_password']
          print_good("SSH user #{admin_name} found with password #{admin_password} and hash #{admin_password_hash}")
          cred = credential_data.dup
          cred[:username] = admin_name
          cred[:private_data] = admin_password_hash
          cred[:private_type] = :nonreplayable_hash
          record = create_credential_and_login(cred)
          unless admin_password.empty?
            # XXX re-enable this
            #puts record.id.to_s
            #puts record
            #create_cracked_credential(username: admin_name, password: admin_password, core_id: record.id)
          end
          line['x_ssh_keys'].each do |key| # XXX test this
            print_good("SSH user #{admin_name} found with SSH key #{key}")
          end
        end
      end
    end

    # here is where we actually process the file
    config.each do |key,value|
      case key
      when 'admin'
        process_admin(value, credential_data)
      when 'radiusprofile'
        process_radiusprofile(value, credential_data)
      when 'setting'
        process_settings(value, credential_data)
      end
    end

  end
end
end
