##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/http_post'
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
        'Name' => 'Damn Vulnerable Web Application login utility',
        'Description' => %q{
          This module will attempt to authenticate to the Damn Vulnerable Web App login page.
        },
        'Author' => [ '3V3RYONE' ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 80,
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [ARTIFACTS_ON_DISK]
        }
      )
    )

    deregister_options('PASSWORD_SPRAY')
    register_options(
      [
        OptString.new('AUTH_URI', [true, 'The URI to authenticate to', '']),
      ]
    )
  end

  def scanner(ip)
    @scanner ||= lambda {
      cred_collection = build_credential_collection(
        username: datastore['HttpUsername'],
        password: datastore['HttpPassword']
      )

      return Metasploit::Framework::LoginScanner::HttpPostBruteforce.new(
        configure_http_login_scanner(
          uri: datastore['AUTH_URI'],
          host: ip,
          port: datastore['RPORT'],
          cred_details: cred_collection,
          stop_on_success: datastore['STOP_ON_SUCCESS'],
          bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
          connection_timeout: 5,
          http_username: datastore['HttpUsername'],
          http_password: datastore['HttpPassword']
        )
      )
    }.call
  end

  def report_good_cred(ip, port, result)
    service_data = {
      address: ip,
      port: port,
      service_name: 'http',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: result.credential.private,
      private_type: :password,
      username: result.credential.public
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      last_attempted_at: DateTime.now,
      status: result.status,
      proof: result.proof
    }.merge(service_data)

    create_credential_login(login_data)
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

  # Attempts to login
  def bruteforce(ip)
    scanner(ip).scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute(level: :good, ip: ip, msg: "Success: '#{result.credential}'")
        report_good_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute(level: :verror, ip: ip, msg: result.proof)
        report_bad_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute(level: :verror, ip: ip, msg: "Failed: '#{result.credential}'")
        report_bad_cred(ip, rport, result)
      end
    end
  end

  # Start here
  def run_host(ip)
    unless scanner(ip).check_setup
      print_brute(level: :error, ip: ip, msg: 'Target not Verified')
      return
    end

    bruteforce(ip)
  end
end
