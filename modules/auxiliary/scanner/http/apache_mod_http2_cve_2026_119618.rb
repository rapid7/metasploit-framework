##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache HTTP Server mod_http2 CVE-2026-119618 Version Scanner',
        'Description' => %q{
          Detection-only scanner for CVE-2026-119618, a race condition in Apache
          httpd mod_http2 (versions 2.4.55 through 2.4.70) that leads to
          unauthenticated remote code execution on servers with HTTP/2 enabled
          (fixed in 2.4.71). This module reads the Server banner, checks whether the
          reported Apache version falls in the affected range, and reports whether
          HTTP/2 is advertised. It performs NO exploitation and sends only a benign
          GET request.

          Caveat: Linux distributions backport the fix WITHOUT changing the version
          string, so a banner in range is a LEAD TO VERIFY, not proof of exposure.
          mod_http2 can also be enabled without advertising h2 on a plaintext
          response; confirm HTTP/2 on TLS via ALPN.
        },
        'Author' => ['Mayur Agnihotri (StraightArc)'],
        'References' => [
          ['CVE', '2026-119618'],
          ['URL', 'https://httpd.apache.org/security/vulnerabilities_24.html'],
          ['URL', 'https://access.redhat.com/security/vulnerabilities/RHSB-2026-017'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2026-119618']
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2026-11-11',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
  end

  def affected_version?(ver)
    Rex::Version.new(ver) >= Rex::Version.new('2.4.55') &&
      Rex::Version.new(ver) <= Rex::Version.new('2.4.70')
  end

  def run_host(ip)
    res = send_request_cgi('method' => 'GET', 'uri' => '/')
    unless res
      vprint_error('no response')
      return
    end

    server = res.headers['Server']
    report_service(host: ip, port: rport, proto: 'tcp', name: (datastore['SSL'] ? 'https' : 'http'), info: server)

    if server.nil? || server.empty?
      vprint_status('no Server header (banner suppressed); cannot assess by version')
      return
    end

    m = server.match(%r{Apache/(\d+\.\d+\.\d+)}i)
    unless m
      vprint_status("Server header exposes no Apache version: #{server}")
      return
    end
    ver = m[1]

    # HTTP/2 advertisement is a confidence signal only. Parse Upgrade and Alt-Svc
    # separately and match only complete h2/h2c protocol identifiers - not a substring
    # of an authority or other token (e.g. Alt-Svc: h3="h2.example:443").
    upgrade = res.headers['Upgrade'].to_s
    alt_svc = res.headers['Alt-Svc'].to_s
    h2_upgrade = upgrade.split(/[\s,]+/).any? { |tok| tok.casecmp?('h2') || tok.casecmp?('h2c') }
    h2_altsvc = alt_svc.match?(/(?:\A|[\s,])h2c?=/i)
    h2 = h2_upgrade || h2_altsvc

    unless affected_version?(ver)
      vprint_status("Apache/#{ver} is outside the affected range (2.4.55-2.4.70)")
      return
    end

    detail = "Apache/#{ver} in CVE-2026-119618 range (2.4.55-2.4.70)"
    detail += h2 ? '; HTTP/2 advertised' : '; HTTP/2 not advertised in headers (confirm via TLS ALPN)'
    detail += '. NOTE: distro backports may patch without changing the version string - verify.'

    print_good(detail)
    report_vuln(
      host: ip,
      port: rport,
      proto: 'tcp',
      name: name,
      info: "#{server} - #{detail}",
      refs: references
    )
  end
end
