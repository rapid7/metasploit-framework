require 'metasploit/framework/login_scanner/sonicwall'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'name' => 'SonicWall HTTP Login Scanner',
        'Description' => %q{This module adds HTTP Login scanning for SonicWall NSv. It allows scanning both admin and user accounts.},
        'Author' => ['msutovsky-r7'],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 4433
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS]
        }
      )
    )
    register_options([
      OptString.new('DOMAIN', [true, 'Select whether to test admin account', 'LocalDomain'])
    ])
  end

  def get_scanner(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS']
    )
    configuration = configure_http_login_scanner(
      host: ip,
      port: datastore['RPORT'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      connection_timeout: datastore['HttpClientTimeout']
    )
    Metasploit::Framework::LoginScanner::SonicWall.new(configuration, datastore['DOMAIN'])
  end

  def process_credential(credential_data)
    credential_combo = "#{credential_data[:username]}:#{credential_data[:private_data]}"
    case credential_data[:status]
    when Metasploit::Model::Login::Status::SUCCESSFUL
      print_good "#{credential_data[:address]}:#{credential_data[:port]} - Login Successful: #{credential_combo}"
      credential_data[:core] = create_credential(credential_data)
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
    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(module_fullname: fullname, workspace_id: myworkspace_id)
      process_credential(credential_data)
    end
  end

  def run_host(ip)
    scanner = get_scanner(ip)
    run_scanner(scanner)
  end

end
