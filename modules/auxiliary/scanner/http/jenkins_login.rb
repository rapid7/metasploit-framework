##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/jenkins'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'           => 'Jenkins-CI Login Utility',
      'Description'    => 'This module attempts to login to a Jenkins-CI instance using a specific user/pass.',
      'Author'         => [ 'Nicholas Starke <starke.nicholas[at]gmail.com>' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptEnum.new('HTTP_METHOD', [true, 'The HTTP method to use for the login', 'POST', ['GET', 'POST']]),
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [ false, 'The path to the Jenkins-CI application'])
      ])

    register_autofilter_ports([ 80, 443, 8080, 8081, 8000 ])
  end

  def run_host(ip)
    print_warning("#{fullname} is still calling the deprecated LOGIN_URL option! This is no longer supported.") unless datastore['LOGIN_URL'].nil?
    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    scanner = Metasploit::Framework::LoginScanner::Jenkins.new(
      configure_http_login_scanner(
        uri: target_uri,
        method: datastore['HTTP_METHOD'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 10,
        http_username: datastore['HttpUsername'],
        http_password: datastore['HttpPassword']
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(module_fullname: fullname, workspace_id: myworkspace_id)

      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - Login Successful: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status})"
      end
    end
  end

  private

  # This method uses the provided URI to determine whether login is possible for Jenkins.
  # Based on the contents of the provided URI, the method looks for the login form and
  # extracts the endpoint used to authenticate against.
  #
  # @param [URI, String] target_uri The targets URI
  # @return [String, nil] URI for successful login
  def jenkins_uri_check(target_uri, keep_cookies: false)
    # if keep_cookies is true we get the first cookie that's needed by newer Jenkins versions
    res = send_request_cgi({ 'uri' => normalize_uri(target_uri, 'login'), 'keep_cookies' => keep_cookies })

    fail_with(Msf::Module::Failure::UnexpectedReply, 'Unexpected reply from server') unless valid_response?(res)

    if res&.body =~ /action="(j_([a-z0-9_]+))"/
      uri = Regexp.last_match(1)
    else
      fail_with(Msf::Module::Failure::UnexpectedReply, 'Failed to identify the login resource.')
    end

    normalize_uri(target_uri, uri)
  end

  # Determines whether the provided response is considered valid or not.
  #
  # @param [Rex::Proto::Http::Response, nil] response The response received from the HTTP request.
  # @return [Boolean] True if the response if valid; otherwise false.
  def valid_response?(response)
    response&.code == 200
  end
end
