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
        'Name' => 'Arista VeloCloud Orchestrator (VCO) Version Scanner',
        'Description' => %q{
          This module fingerprints the version of an on-premises Arista (formerly VMware)
          VeloCloud Orchestrator (VCO) web interface and reports whether the detected
          version falls within a range affected by CVE-2026-93952, a critical improper
          input validation flaw (CWE-20) scored by Arista PSIRT as CVSS v3.1 10.0 and
          CVSS v4.0 9.5.

          This is a detection-only module: it makes no attempt to exploit the flaw. It
          reports on version alone. Note that CVE-2026-93952 only affects orchestrators
          configured for certificate-based Edge-to-VCO authentication (Certificate Acquire
          or Certificate Required modes), which cannot be reliably determined remotely by
          version fingerprinting. A "Vulnerable" result therefore means "running an affected
          version"; operators must confirm the Edge authentication mode to establish actual
          exposure.
        },
        'Author' => [
          'enp7s0d' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2026-93952' ],
          [ 'URL', 'https://www.arista.com/en/support/advisories-notices/security-advisory/24765-security-advisory-0183' ],
          [ 'URL', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-93952' ]
        ],
        'DisclosureDate' => '2026-09-22',
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 443
        },
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => [ REPEATABLE_SESSION ]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [ true, 'The base path to the VeloCloud Orchestrator', '/' ])
    ])
  end

  # Fixed release per affected train. A version is affected when it is less than
  # the fixed release within the same major.minor train. Trains with no published
  # fix as of the disclosure date (6.1 and 7.0) are treated as affected for any
  # release at or below the last-known affected build.
  #
  # Source: Arista advisory / public reporting for CVE-2026-93952.
  #   5.2 train: affected <= 5.2.3.15, fixed 5.2.3.16
  #   6.1 train: affected <= 6.1.3.7,  fix pending
  #   6.4 train: affected <= 6.4.2.7,  fixed 6.4.2.8
  #   7.0 train: affected <= 7.0.0.2,  fix pending
  FIXED_VERSIONS = {
    '5.2' => Rex::Version.new('5.2.3.16'),
    '6.4' => Rex::Version.new('6.4.2.8')
  }.freeze

  # Trains with no fix yet: affected at or below this build.
  LAST_AFFECTED = {
    '6.1' => Rex::Version.new('6.1.3.7'),
    '7.0' => Rex::Version.new('7.0.0.2')
  }.freeze

  # MurmurHash3 (mmh3) of the VCO favicon, the one confirmed *unauthenticated*
  # fingerprint for the product. It identifies VeloCloud Orchestrator but says
  # nothing about the version, so it is used only to confirm the target is a VCO
  # before the (best-effort) version read.
  #
  # Provenance and validation: the ProjectDiscovery favicon-detect template maps
  # this value to "arista-velocloud" via mmh3(base64_py(body)) (i.e. mmh3 over
  # the Python base64.encodebytes of the favicon), which is exactly what
  # favicon_mmh3 reproduces below. The same Shodan dork (http.favicon.hash:
  # -2062596654) is used to census VeloCloud Orchestrators in public SD-WAN
  # reconnaissance research. The constant has been reproduced against two live
  # Arista-hosted Orchestrators (vco1-usvi1 and vco996-usvi1.velocloud.net) by
  # fetching /apps/root/favicon.ico and hashing it with both this Ruby code and
  # the reference Python mmh3 implementation.
  #   https://github.com/projectdiscovery/nuclei-templates/blob/main/http/technologies/favicon-detect.yaml
  VCO_FAVICON_MMH3 = -2062596654

  # Candidate favicon URIs tried in order. /apps/root/favicon.ico is where the
  # current Arista Angular SPA actually serves the icon. /favicon.ico is kept
  # as a fallback for older VMware-era builds; on current builds the SPA router
  # intercepts that path and returns the landing HTML, which hashes differently.
  FAVICON_PATHS = [ 'apps/root/favicon.ico', 'favicon.ico' ].freeze

  def vulnerable?(version)
    train = version.segments.take(2).join('.')

    if FIXED_VERSIONS.key?(train)
      return version < FIXED_VERSIONS[train]
    end

    if LAST_AFFECTED.key?(train)
      return version <= LAST_AFFECTED[train]
    end

    # Unknown train: cannot make a determination on version alone.
    nil
  end

  # Extract the VCO version from the web interface.
  #
  # NOTE: on the current Arista-era builds tested here (hosted VCOs at
  # vco1-usvi1 and vco996-usvi1.velocloud.net, SPA last-modified 2026-10-22),
  # no unauthenticated endpoint exposes a build version string:
  #   - /portal/ and /portal/rest/ both return 404.
  #   - The Angular SPA entry (/apps/root/main.js) only loads
  #     /apps/root/assets/module-federation.manifest.json, which is empty ({})
  #     until the user authenticates; the microfrontends that carry version
  #     metadata are registered post-login.
  #   - No Server / X-*-Version response headers are emitted.
  # The best-effort candidates below (a build string in the SPA bundle or
  # landing page) are kept so that (a) older VMware-era builds that do leak a
  # version string still get a Vulnerable/Not vulnerable verdict, and (b) if a
  # future build exposes one at /portal/, the code is already in place. On
  # builds like the one tested, get_version returns nil and run_host stops at
  # product detection, which the maintainer-visible output makes explicit.
  def get_version
    # Candidate 1: a version string embedded in the portal landing page / JS bundle.
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'portal', '/')
    )

    if res && res.code == 200 && res.body
      # e.g. "buildVersion":"R5230-20260101" or a plain semantic version in the bundle
      if res.body =~ /buildVersion["']?\s*[:=]\s*["']?R?(\d+\.\d+\.\d+(?:\.\d+)?)/i
        return Rex::Version.new(Regexp.last_match(1))
      end

      if res.body =~ /VeloCloud[^<]*?(\d+\.\d+\.\d+(?:\.\d+)?)/i
        return Rex::Version.new(Regexp.last_match(1))
      end
    end

    nil
  end

  # Fetch the site favicon at the given path and return its Shodan/nuclei-
  # compatible mmh3 hash, or nil if no favicon is served. The hash is computed
  # over the base64 encoding of the raw favicon bytes, wrapped at 76 characters
  # with a trailing newline, which is what Shodan (Python base64.encodebytes)
  # and the ProjectDiscovery templates hash. Ruby's Base64.encode64 wraps at 60
  # characters and would produce a different value, so the encoding is done
  # explicitly here.
  def favicon_mmh3(path = 'favicon.ico')
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, path)
    )
    return nil unless res && res.code == 200 && res.body && !res.body.empty?

    b64 = [res.body.to_s.b].pack('m0').scan(/.{1,76}/).join("\n") + "\n"
    mmh3_x86_32(b64)
  end

  # Try each candidate favicon URI in order; return true as soon as one matches
  # VCO_FAVICON_MMH3.
  def favicon_match?
    FAVICON_PATHS.any? { |p| favicon_mmh3(p) == VCO_FAVICON_MMH3 }
  end

  # MurmurHash3 x86 32-bit (seed 0), returned as a signed 32-bit integer to match
  # the convention used by Python's mmh3 library, Shodan and nuclei favicon
  # hashes. Reference: Austin Appleby, MurmurHash3 (public domain).
  def mmh3_x86_32(data, seed = 0)
    data = data.b
    c1 = 0xcc9e2d51
    c2 = 0x1b873593
    len = data.bytesize
    h1 = seed & 0xffffffff
    rotl = ->(x, r) { ((x << r) | (x >> (32 - r))) & 0xffffffff }

    nblocks = len / 4
    nblocks.times do |b|
      k1 = data.byteslice(b * 4, 4).unpack1('V')
      k1 = (k1 * c1) & 0xffffffff
      k1 = rotl.call(k1, 15)
      k1 = (k1 * c2) & 0xffffffff
      h1 ^= k1
      h1 = rotl.call(h1, 13)
      h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    end

    tail = data.byteslice(nblocks * 4, len - nblocks * 4).bytes
    k1 = 0
    k1 ^= tail[2] << 16 if tail.size >= 3
    k1 ^= tail[1] << 8 if tail.size >= 2
    if tail.size >= 1
      k1 ^= tail[0]
      k1 = (k1 * c1) & 0xffffffff
      k1 = rotl.call(k1, 15)
      k1 = (k1 * c2) & 0xffffffff
      h1 ^= k1
    end

    h1 ^= len
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= h1 >> 13
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= h1 >> 16

    h1 >= 0x80000000 ? h1 - 0x100000000 : h1
  end

  # Best-effort product identification from the landing page body/headers. Used
  # as a fallback confirmation when the favicon is unavailable; the favicon hash
  # in favicon_mmh3 is the more reliable signal. On current Arista-era builds
  # the SPA landing HTML references "@velocloud/vco-header" (lowercase), which
  # hits the 'velocloud' substring check below.
  def looks_like_vco?(res)
    return false unless res

    body = res.body.to_s
    body.include?('VeloCloud') ||
      body.include?('velocloud') ||
      res.headers.to_s.include?('velocloud')
  end

  # Supplementary signal: /login/ on a VCO always sets Set-Cookie headers whose
  # names are prefixed with "velocloud." (velocloud.session, velocloud.csrf,
  # velocloud.message). Used only as a last resort when neither the favicon nor
  # the landing body match, so most hosts cost no extra request. Only
  # Set-Cookie headers are considered; a non-cookie response header that
  # happens to contain "velocloud." (for example a vendor-branded Server line)
  # must not misidentify an unrelated service.
  def login_cookie_match?
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'login/')
    )
    return false unless res

    res.headers.to_s.each_line.any? do |line|
      line =~ /\ASet-Cookie:\s*velocloud\./i
    end
  end

  def run_host(ip)
    peer = Rex::Socket.to_authority(ip, datastore['RPORT'])
    vprint_status("#{peer} - Checking for VeloCloud Orchestrator")

    landing = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    )

    favicon_match = favicon_match?
    string_match = looks_like_vco?(landing)
    cookie_match = !(favicon_match || string_match) && login_cookie_match?

    unless favicon_match || string_match || cookie_match
      vprint_error("#{peer} - VeloCloud Orchestrator not detected")
      return
    end

    signal = if favicon_match
               'favicon hash'
             elsif string_match
               'page content'
             else
               'login cookie'
             end
    vprint_good("#{peer} - VeloCloud Orchestrator identified via #{signal}")

    # Record the detected service even when the version can't be read, so the
    # host still shows up in the services table for inventory and follow-up.
    report_service(
      host: ip,
      port: datastore['RPORT'],
      proto: 'tcp',
      name: ssl ? 'https' : 'http',
      info: 'Arista VeloCloud Orchestrator'
    )

    version = get_version
    if version.nil?
      print_status("#{peer} - VeloCloud Orchestrator detected, but version could not be determined")
      return
    end

    print_good("#{peer} - VeloCloud Orchestrator version #{version} detected")
    report_note(
      host: ip,
      port: datastore['RPORT'],
      proto: 'tcp',
      ntype: 'velocloud.orchestrator.version',
      data: { version: version.to_s },
      update: :unique_data
    )

    case vulnerable?(version)
    when true
      print_warning("#{peer} - Version #{version} is within a range affected by CVE-2026-93952 " \
                    '(confirm certificate-based Edge authentication is enabled to establish exposure)')
      report_vuln(
        host: ip,
        port: datastore['RPORT'],
        proto: 'tcp',
        name: name,
        info: "VeloCloud Orchestrator #{version} affected by CVE-2026-93952",
        refs: references
      )
    when false
      print_status("#{peer} - Version #{version} is not within a known affected range for CVE-2026-93952")
    else
      print_status("#{peer} - Version #{version} is in an unrecognized release train; unable to assess CVE-2026-93952")
    end
  end
end
