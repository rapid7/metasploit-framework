##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ftp'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def proto
    'ftp'
  end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'FTP Authentication Scanner',
        'Description' => %q{
          This module tests FTP logins on a range of machines. Successful
          logins are recorded in the database as credentials, along with
          host information.
        },
        'Author' => [
          'todb',
          'g0tmi1k' # @g0tmi1k - additional features
        ],
        'References' => [
          [ 'CVE', '1999-0502' ], # Weak password
          [ 'ATT&CK', Mitre::Attack::Technique::T1021_REMOTE_SERVICES ],
          [ 'ATT&CK', Mitre::Attack::Technique::T1110_001_PASSWORD_GUESSING ]
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS, ACCOUNT_LOCKOUTS],
          'Reliability' => []
        },
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'ConnectTimeout' => 30
        }
      )
    )

    register_options(
      [
        Opt::Proxies,
        Opt::RPORT(21),
        OptBool.new('ANONYMOUS_LOGIN', [ true, 'Attempt to login using various anonymous FTP users', false ]), # Overwrite the AuthBrute mixin, as its not sending blank/empty user/pass
        OptBool.new('CHECK_ACCESS', [ false, 'Check READ/WRITE access for successful logins', false ])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SINGLE_SESSION', [ false, 'Disconnect after every login attempt', false ])
      ]
    )

    deregister_options('FTPUSER', 'FTPPASS') # Can use these, but should use 'username' and 'password'
    @accepts_all_logins = {}
  end

  def run_scanner(ip, scanner)
    scanner.scan! do |result|
      unless @reported_banner
        @reported_banner = true
        if scanner.banner&.match?(/^(120|220)[\s-]/)
          self.banner = scanner.banner
          print_brute level: :vstatus, ip: ip, port: rport, msg: "FTP Banner: #{banner_version}"
        end
      end

      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )

      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        yield result, credential_data
        report_ftp_service_and_banner(ip)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        print_brute level: :verror, ip: ip, port: rport, msg: "Could not connect: #{result.proof}"

        invalidate_login(credential_data)

        report_host(host: ip) unless result.proof.to_s.empty?
      else
        print_brute level: :verror, ip: ip, port: rport, msg: "Failed: #{result.credential} (#{result.status}: #{result.proof})"

        invalidate_login(credential_data)

        if !@reported_service && result.status == Metasploit::Model::Login::Status::INCORRECT
          @reported_service = true
          report_ftp_service_and_banner(ip)
        end
      end
    end
  end

  def run_host(ip)
    @reported_banner = false
    @reported_service = false

    print_brute level: :status, ip: ip, port: rport, msg: 'Starting FTP login sweep'

    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD'],
      prepended_creds: anonymous_creds,
      anonymous_login: false # Otherwise this would send blank for both user/password, so its different to anonymous_creds()
    )

    if cred_collection.empty?
      print_brute level: :error, ip: ip, port: rport, msg: 'No credentials specified. Set USERNAME/PASSWORD, USER_FILE/PASS_FILE, or ANONYMOUS_LOGIN'
      return
    end

    scanner = Metasploit::Framework::LoginScanner::FTP.new(
      configure_login_scanner(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        max_send_size: datastore['TCP::max_send_size'],
        send_delay: datastore['TCP::send_delay'],
        connection_timeout: datastore['ConnectTimeout'],
        ftp_timeout: datastore['FTPTimeout'],
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

    run_scanner(ip, scanner) do |result, credential_data|
      credential_data[:private_type] = :password
      credential_core = create_credential(credential_data)
      credential_data[:core] = credential_core

      access_level = nil
      if datastore['CHECK_ACCESS']
        print_brute level: :vstatus, ip: rhost, port: rport, msg: 'Checking read/write access'
        begin
          connect(true, false)
          send_user(result.credential.public)
          if send_pass(result.credential.private).to_s.start_with?('2')
            access_level = test_ftp_access
          end
        rescue ::IOError, Errno::ECONNRESET, ::Timeout::Error => e
          print_brute level: :verror, ip: ip, port: rport, msg: e.message
        ensure
          disconnect
        end
      end

      credential_data[:access_level] = access_level if access_level
      create_credential_login(credential_data)

      msg = "Login Successful: #{result.credential}"
      msg << " (#{access_level})" if access_level
      print_brute level: :good, ip: ip, port: rport, msg: msg
    end
  end

  # Check for anonymous access by pretending to be a browser
  def anonymous_creds
    return [] unless datastore['ANONYMOUS_LOGIN']

    ['mozilla@example.com', 'IEUser@', 'User@', 'chrome@example.com'].map do |password|
      Metasploit::Framework::Credential.new(public: 'anonymous', private: password, private_type: :password)
    end
  end

  def test_ftp_access
    dir = Rex::Text.rand_text_alpha(8)
    write_check = send_cmd(['MKD', dir], true)
    if write_check && write_check.start_with?('2')
      send_cmd(['RMD', dir], true)
      'Read/Write'
    else
      'Read-only'
    end
  end

  def report_ftp_service_and_banner(ip)
    report_service(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: 'ftp',
      info: banner ? Rex::Text.to_hex_ascii(banner_version) : nil,
      parents: {
        host: ip,
        port: rport,
        proto: 'tcp',
        name: 'tcp'
      }
    )

    return unless banner

    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      sname: 'ftp',
      type: 'ftp.banner',
      data: { banner: Rex::Text.to_hex_ascii(banner.strip) }
    )
  end
end
