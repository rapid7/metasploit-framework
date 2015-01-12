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

  def check_response_fingerprint(res, fallback_status)
    fp = http_fingerprint(response: res)
    if /RomPager\/(?<version>[\d\.]+)/ =~ fp
      vprint_status("#{peer} is RomPager #{version}")
      if Gem::Version.new(version) < Gem::Version.new('4.34')
        return Exploit::CheckCode::Detected
      end
    end
    fallback_status
  end

  def find_canary
    vprint_status("#{peer} locating suitable canary URI")
    0.upto(4) do
      canary = '/' + Rex::Text.rand_text_alpha(16)
      res = send_request_raw(
        'uri' => normalize_uri(canary),
        'method' => 'GET',
        'headers' => headers
      )
      # in most cases, the canary URI will not exist and will return a 404, but
      # if everything under TARGETURI is protected by auth, that may be fine
      # too
      return canary if res.code == 401 || res.code == 404
    end
    nil
  end

  def headers
    {
      'Referer' => full_uri
    }
  end

  # To test for this vulnerability, we must first find a URI known to return
  # a 404 (not found) which we will use as a canary.  This URI (for example,
  # /foo) is then taken and used as the value for a carefully crafted cookie
  # when making a request to the configured host+port+uri.  If the response
  # is a 404 and the body includes the canary, it is likely that the cookie
  # overwrote RomPager's concept of the requested URI, indicating that it is
  # vulnerable.
  def test_misfortune
    # find a usable canary URI (one that returns a 404 already)
    unless (canary_value = find_canary)
      vprint_error("#{peer} Unable to find a suitable canary URI")
      return Exploit::CheckCode::Unknown
    end

    canary_cookie_name = 'C107373883'
    canary_cookie = canary_cookie_name + "=#{canary_value};"

    # Make a request containing a specific canary cookie name with the value set
    # from the suitable canary value found above.
    res = send_request_raw(
      'uri' => normalize_uri(target_uri.path.to_s),
      'method' => 'GET',
      'headers' => headers.merge('Cookie' => canary_cookie)
    )

    unless res
      vprint_error("#{full_uri} no response")
      return Exploit::CheckCode::Unknown
    end

    unless res.code == 404
      vprint_status("#{full_uri} unexpected HTTP code #{res.code} response")
      return check_response_fingerprint(res, Exploit::CheckCode::Unknown)
    end

    unless res.body
      vprint_status("#{full_uri} HTTP code #{res.code} had no body")
      return check_response_fingerprint(res, Exploit::CheckCode::Unknown)
    end

    # If that canary *value* shows up in the *body*, then there are two possibilities:
    #
    # 1) If the canary cookie *name* is also in the *body*, it is likely that
    # the endpoint is puppeting back our request to some extent and therefore
    # it is expected that the canary cookie *value* would also be there.
    # return Exploit::CheckCode::Unknown
    #
    # 2) If the canary cookie *name* is *not* in the *body*, return
    # Exploit::CheckCode::Appears
    if res.body.include?(canary_value)
      if res.body.include?(canary_cookie_name)
        vprint_status("#{full_uri} HTTP code #{res.code} response contained test cookie name #{canary_cookie_name}")
        return check_response_fingerprint(res, Exploit::CheckCode::Unknown)
      else
        vprint_good("#{full_uri} HTTP code #{res.code} response contained canary cookie value #{canary_value} as URI")
        report_vuln(
          host: rhost,
          port: rport,
          name: name,
          refs: references
        )
        return Exploit::CheckCode::Appears
      end
    end

    vprint_status("#{full_uri} HTTP code #{res.code} response did not contain canary cookie value #{canary_value} as URI")
    check_response_fingerprint(res, Exploit::CheckCode::Safe)
  end
end
