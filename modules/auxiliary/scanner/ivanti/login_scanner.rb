require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ivanti_login'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::ReportSummary

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ivanti Connect Secure HTTP Scanner',
        'Description' => %q{
          This module will perform authentication scanning against Ivanti Connect Secure
        },
        'Author' => ['msutovsky-r7'],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS]
        }
      )
         )
    register_options([
      OptBool.new('ADMIN', [true, 'Select whether to test admin account', false])
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
      connection_timeout: datastore['HttpClientTimeout'] || 5
    )
    return Metasploit::Framework::LoginScanner::Ivanti.new(configuration, datastore['ADMIN'])
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
