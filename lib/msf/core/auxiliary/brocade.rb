# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for working with Brocade equipment
#
###
module Auxiliary::Brocade
  include Msf::Auxiliary::Report

  def create_credential_and_login(opts={})
    return nil unless active_db?

    if self.respond_to?(:[]) and self[:task]
      opts[:task_id] ||= self[:task].record.id
    end

    core               = opts.fetch(:core, create_credential(opts))
    access_level       = opts.fetch(:access_level, nil)
    last_attempted_at  = opts.fetch(:last_attempted_at, nil)
    status             = opts.fetch(:status, Metasploit::Model::Login::Status::UNTRIED)

    login_object = nil
    retry_transaction do
      service_object = create_credential_service(opts)
      login_object = Metasploit::Credential::Login.where(core_id: core.id, service_id: service_object.id).first_or_initialize

      if opts[:task_id]
        login_object.tasks << Mdm::Task.find(opts[:task_id])
      end

      login_object.access_level      = access_level if access_level
      login_object.last_attempted_at = last_attempted_at if last_attempted_at
      if status == Metasploit::Model::Login::Status::UNTRIED
        if login_object.last_attempted_at.nil?
          login_object.status = status
        end
      else
        login_object.status = status
      end
      login_object.save!
    end

    login_object
  end
  

  def brocade_config_eater(thost, tport, config)
    # this is for brocade type devices.
    # It is similar to cisco
    # Docs: enable password-display -> http://wwwaem.brocade.com/content/html/en/command-reference-guide/fastiron-08040-commandref/GUID-169889CD-1A74-4A23-AC78-38796692374F.html

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

    store_loot('brocade.config', 'text/plain', thost, config.strip, 'config.txt', 'Brocade Configuration')

    # Brocade has this one configuration called "password display". With it, we get hashes. With out it, just ...
    if config =~ /enable password-display/
      print_good('password-display is enabled, hashes will be displayed in config')
    else
      print_bad('password-display is disabled, no password hashes displayed in config')
    end

    # enable password
    # Example lines:
    # enable super-user-password 8 $1$QP3H93Wm$uxYAs2HmAK01QiP3ig5tm.
    config.scan(/enable super-user-password 8 (?<admin_password_hash>.+)/i).each do |result|
      admin_hash = result[0].strip
      unless admin_hash == '.....'
        print_good("enable password hash #{admin_hash}")
        cred = credential_data.dup
        cred[:username] = 'enable'
        cred[:private_data] = admin_hash
        cred[:private_type] = :nonreplayable_hash
        create_credential_and_login(cred)
      end
    end

    # user account
    # Example lines:
    # username brocade password 8 $1$YBaHUWpr$PzeUrP0XmVOyVNM5rYy99/
    config.scan(/username "?(?<user_name>[a-z0-9]+)"? password (?<user_type>\w+) (?<user_hash>[0-9a-z=\$\/]{34})/i).each do |result|
      user_name = result[0].strip
      user_type  = result[1].strip
      user_hash = result[2].strip
      unless user_hash == '.....'
        print_good("User #{user_name} of type #{user_type} found with password hash #{user_hash}.")
        cred = credential_data.dup
        cred[:username] = user_name
        cred[:private_data] = user_hash
        cred[:private_type] = :nonreplayable_hash
        create_credential_and_login(cred)
      end
    end

    # snmp
    # Example lines: 
    # snmp-server community 1 $Si2^=d rw
    # these at times look base64 encoded, which they may be, but are also encrypted
    config.scan(/snmp-server community (?<snmp_id>[\d]+) (?<snmp_community>.+) (?<snmp_permissions>rw|ro)/i).each do |result|
      snmp_community = result[1].strip
      snmp_permissions = result[2].strip
      unless snmp_community == '.....'
        print_good("#{'ENCRYPTED ' if snmp_community.start_with?('$')}SNMP community #{snmp_community} with permissions #{snmp_permissions}")
        cred = credential_data.dup
        cred[:protocol] = 'udp'
        cred[:port] = 161
        cred[:service_name] = 'snmp'
        cred[:private_data] = snmp_community
        cred[:private_type] = :nonreplayable_hash
        create_credential_and_login(cred)
      end
    end

  end
end
end

