# -*- coding: binary -*-

require 'metasploit/framework/hashes/identify'

module Msf

###
#
# This module provides methods for working with Juniper equipment
#
###
module Auxiliary::Juniper
  include Msf::Auxiliary::Report

  def juniper_screenos_config_eater(thost, tport, config)
    # this is for the netscreen OS, which came on SSG (ie SSG5) type devices.
    # It is similar to cisco, however it doesn't always put all fields we care
    # about on one line.
    # Docs: snmp -> https://kb.juniper.net/InfoCenter/index?page=content&id=KB4223
    #       ppp  -> https://kb.juniper.net/InfoCenter/index?page=content&id=KB22592
    #       ike  -> https://kb.juniper.net/KB4147
    #       https://github.com/h00die/MSF-Testing-Scripts/blob/master/juniper_strings.py#L171

    report_host({
      :host => thost,
      :os_name => 'Juniper ScreenOS'
    })

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

    store_loot('juniper.netscreen.config', 'text/plain', thost, config.strip, 'config.txt', 'Juniper Netscreen Configuration')

    # admin name and password
    # Example lines:
    # set admin name "netscreen"
    # set admin password "nKVUM2rwMUzPcrkG5sWIHdCtqkAibn"
    config.scan(/set admin name "(?<admin_name>[a-z0-9]+)".+set admin password "(?<admin_password_hash>[a-z0-9]+)"/mi).each do |result|
      admin_name = result[0].strip
      admin_hash = result[1].strip
      print_good("Admin user #{admin_name} found with password hash #{admin_hash}")
      cred = credential_data.dup
      cred[:username] = admin_name
      cred[:private_data] = admin_hash
      cred[:private_type] = :nonreplayable_hash
      create_credential_and_login(cred)
    end

    # user account
    # Example lines:
    # set user "testuser" uid 1
    # set user "testuser" type auth
    # set user "testuser" hash-password "02b0jt2gZGipCiIEgl4eainqZIKzjSNQYLIwE="
    # set user "testuser" enable
    config.scan(/set user "(?<user_name>[a-z0-9]+)" uid (?<user_uid>\d+).+set user "\k<user_name>" type (?<user_type>\w+).+set user "\k<user_name>" hash-password "(?<user_hash>[0-9a-z=]{38})".+set user "\k<user_name>" (?<user_enable>enable).+/mi).each do |result|
      user_name = result[0].strip
      user_uid  = result[1].strip
      user_enable = result[4].strip
      user_hash = result[3].strip
      print_good("User #{user_uid} named #{user_name} found with password hash #{user_hash}. Enable permission: #{user_enable}")
      cred = credential_data.dup
      cred[:username] = user_name
      cred[:jtr_format] = 'sha1'
      cred[:private_data] = user_hash
      cred[:private_type] = :nonreplayable_hash
      create_credential_and_login(cred)
    end

    # snmp
    # Example lines: 
    # set snmp community "sales" Read-Write Trap-on traffic version v1
    config.scan(/set snmp community "(?<snmp_community>[a-z0-9]+)" (?<snmp_permissions>Read-Write|Read-Only)/i).each do |result|
      snmp_community = result[0].strip
      snmp_permissions = result[1].strip
      print_good("SNMP community #{snmp_community} with permissions #{snmp_permissions}")
      cred = credential_data.dup
      if snmp_permissions.downcase == 'read-write'
        cred[:access_level] = 'RW'
      else
        cred[:access_level] = 'RO'
      end
      cred[:protocol] = 'udp'
      cred[:port] = 161
      cred[:service_name] = 'snmp'
      cred[:private_data] = snmp_community
      cred[:private_type] = :password
      create_credential_and_login(cred)
    end

    # ppp
    # Example lines:
    # setppp profile "ISP" auth type pap
    # setppp profile "ISP" auth local-name "username"
    # setppp profile "ISP" auth secret "fzSzAn31N4Sbh/sukoCDLvhJEdn0DVK7vA=="
    config.scan(/setppp profile "(?<ppp_name>[a-z0-9]+)" auth type (?<ppp_authtype>[a-z]+).+setppp profile "\k<ppp_name>" auth local-name "(?<ppp_username>[a-z0-9]+)".+setppp profile "\k<ppp_name>" auth secret "(?<ppp_hash>.+)"/mi).each do |result|
      ppp_name = result[0].strip
      ppp_username = result[2].strip
      ppp_hash = result[3].strip
      ppp_authtype = result[1].strip
      print_good("PPTP Profile #{ppp_name} with username #{ppp_username} hash #{ppp_hash} via #{ppp_authtype}")
      cred = credential_data.dup
      cred[:username] = ppp_username
      cred[:private_data] = ppp_hash
      cred[:service_name] = 'PPTP'
      cred[:port] = 1723
      cred[:private_type] = :nonreplayable_hash
      create_credential_and_login(cred)
    end

    # ike
    # Example lines:
    # set ike gateway "To-Cisco" address 2.2.2.1 Main outgoing-interface "ethernet1" preshare "netscreen" proposal "pre-g2-des-sha"
    config.scan(/set ike gateway "(?<ike_name>.+)" address (?<ike_address>[0-9.]+) Main outgoing-interface ".+" preshare "(?<ike_password>.+)" proposal "(?<ike_method>.+)"/i).each do |result|
      ike_name = result[0].strip
      ike_address = result[1].strip
      ike_password = result[2].strip
      ike_method = result[3].strip
      print_good("IKE Profile #{ike_name} to #{ike_address} with password #{ike_password} via #{ike_method}")
      cred = credential_data.dup
      cred[:private_data] = ike_password
      cred[:private_type] = :password
      cred[:service_name] = 'IKE'
      cred[:port] = 500
      cred[:address] = ike_address
      cred[:protocol] = 'udp'
      create_credential_and_login(cred)
    end

  end


  def juniper_junos_config_eater(thost, tport, config)

   report_host({
      :host => thost,
      :os_name => 'Juniper JunOS'
    })


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

    store_loot('juniper.junos.config', 'text/plain', thost, config.strip, 'config.txt', 'Juniper JunOS Configuration')

    # we'll take out the pretty format so its easier to regex
    config = config.split("\n").join('')

    # Example:
    #system {
    #  root-authentication {
    #    encrypted-password "$1$pz9b1.fq$foo5r85Ql8mXdoRUe0C1E."; ## SECRET-DATA
    #  }
    #}
    if /root-authentication[\s]+\{[\s]+encrypted-password "(?<root_hash>[^"]+)";/i =~ config
      root_hash = root_hash.strip
      jtr_format = identify_hash root_hash

      print_good("root password hash: #{root_hash}")
      cred = credential_data.dup
      cred[:username] = 'root'
      cred[:jtr_format] = jtr_format
      cred[:private_data] = root_hash
      cred[:private_type] = :nonreplayable_hash
      create_credential_and_login(cred)
    end

    # access privileges https://kb.juniper.net/InfoCenter/index?page=content&id=KB10902
    config.scan(/user (?<user_name>[^\s]+) {[\s]+ uid (?<user_uid>[\d]+);[\s]+ class (?<user_permission>super-user|operator|read-only|unauthorized);[\s]+ authentication {[\s]+encrypted-password "(?<user_hash>[^\s]+)";/i).each do |result|
      user_name = result[0].strip
      user_uid  = result[1].strip
      user_permission = result[2].strip
      user_hash = result[3].strip
      jtr_format = identify_hash user_hash

      print_good("User #{user_uid} named #{user_name} in group #{user_permission} found with password hash #{user_hash}.")
      cred = credential_data.dup
      cred[:username] = user_name
      cred[:jtr_format] = jtr_format
      cred[:private_data] = user_hash
      cred[:private_type] = :nonreplayable_hash
      create_credential_and_login(cred)
    end

    # https://supportf5.com/csp/article/K6449 special characters allowed in snmp community strings
    config.scan(/community "?(?<snmp_community>[\w\d\s\(\)\.\*\/-:_\?=@\,&%\$]+)"? {(\s+view [\w\-]+;)?\s+authorization read-(?<snmp_permission>only|write)/i).each do |result|
      snmp_community = result[0].strip
      snmp_permissions = result[1].strip
      print_good("SNMP community #{snmp_community} with permissions read-#{snmp_permissions}")
      cred = credential_data.dup
      if snmp_permissions.downcase == 'write'
        cred[:access_level] = 'RW'
      else
        cred[:access_level] = 'RO'
      end
      cred[:protocol] = 'udp'
      cred[:port] = 161
      cred[:private_data] = snmp_community
      cred[:private_type] = :password
      cred[:service_name] = 'snmp'
      create_credential_and_login(cred)
    end    

    config.scan(/radius-server \{[\s]+(?<radius_server>[0-9\.]{7,15}) secret "(?<radius_hash>[^"]+)";/i).each do |result|
      radius_hash = result[1].strip
      radius_server = result[0].strip
      print_good("radius server #{radius_server} password hash: #{radius_hash}")
      cred = credential_data.dup
      cred[:address] = radius_server
      cred[:port] = 1812
      cred[:protocol] = 'udp'
      cred[:private_data] = radius_hash
      cred[:private_type] = :nonreplayable_hash
      cred[:service_name] = 'radius'
      create_credential_and_login(cred)
    end

    config.scan(/pap {[\s]+local-name "(?<ppp_username>.+)";[\s]+local-password "(?<ppp_hash>[^"]+)";/i).each do |result|
      ppp_username = result[0].strip
      ppp_hash = result[1].strip
      print_good("PPTP username #{ppp_username} hash #{ppp_hash} via PAP")
      cred = credential_data.dup
      cred[:username] = ppp_username
      cred[:private_data] = ppp_hash
      cred[:service_name] = 'pptp'
      cred[:port] = 1723
      cred[:private_type] = :nonreplayable_hash
      create_credential_and_login(cred)
    end

  end
end
end

