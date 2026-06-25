##
##
# CVE-2026-0265 PAN-OS GlobalProtect CAS Exposure and Version Scanner
#
# Safe scanner: no authentication bypass attempted, no session creation,
# no body modification, and no firewall state changes.
#
# Detection logic derived from:
# https://github.com/BishopFox/CVE-2026-0265-check
#
# Copyright (c) Bishop Fox
# Original utility released under the MIT License.
#
# This Metasploit module is distributed under the Metasploit Framework license.
##
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  DEFAULT_USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ' \
                       '(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36'

  # Per-base patched-hotfix cutoffs from Bishop Fox scanner / PA advisory logic.
  # Any hotfix strictly below the listed value on the same base is vulnerable.
  ADVISORY_PATCHED_HOTFIX = {
    [10, 2, 4 ] => 44,
    [10, 2, 7 ] => 34,
    [10, 2, 10] => 36,
    [10, 2, 13] => 21,
    [10, 2, 16] => 7,
    [10, 2, 18] => 6,
    [11, 1, 4 ] => 33,
    [11, 1, 6 ] => 32,
    [11, 1, 7 ] => 6,
    [11, 1, 10] => 25,
    [11, 1, 13] => 5,
    [11, 2, 4 ] => 17,
    [11, 2, 7 ] => 13,
    [11, 2, 10] => 6,
    [12, 1, 4 ] => 5
  }.freeze

  # Train-base floors: anything >= this base in the train is patched.
  ADVISORY_BASE_FLOOR = {
    [11, 1] => 15,
    [11, 2] => 12,
    [12, 1] => 7
  }.freeze

  UNAFFECTED_TRAINS = [
    [8, 1],
    [9, 1]
  ].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PAN-OS GlobalProtect CAS CVE-2026-0265 Vulnerability Checker',
        'Description' => %q{
          This module checks a PAN-OS GlobalProtect portal for CVE-2026-0265
          using the Bishop Fox scanner decision flow. It performs a single
          anonymous GET request to the GlobalProtect prelogin endpoint, checks
          whether CAS authentication is enabled, decodes the embedded SAML/JWT
          token when present, extracts PanOSversion, and compares it against
          the advisory version matrix.
        },
        'Author' => [
          'Bishop Fox Team X', # original scanner logic
          'Rapid7 Research / Deral Heiland adaptation' # Metasploit port workflow
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-0265'],
          ['URL', 'https://security.paloaltonetworks.com/CVE-2026-0265']
        ],
        'DisclosureDate' => '2026-05-21',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('SSL', [true, 'Use SSL/TLS', true]),
        OptString.new('TARGETURI', [true, 'GlobalProtect prelogin endpoint path', '/global-protect/prelogin.esp']),
        OptString.new('USERAGENT', [true, 'User-Agent used for the prelogin probe', DEFAULT_USER_AGENT]),
        OptInt.new('TIMEOUT', [true, 'HTTP request timeout in seconds', 20]),
        OptInt.new('RETRIES', [true, 'Number of retries for transient failures or HTTP 503', 3])
      ]
    )
  end

  def run_host(ip)
    finding = scan_target
    target = target_label(ip)

    print_status("#{target} - CAS enabled: #{finding[:cas_enabled]}")
    print_status("#{target} - PAN-OS version: #{finding[:panos_version] || 'unknown'}")

    case finding[:verdict]
    when 'VULNERABLE'
      print_good("#{target} - Status: VULNERABLE")
      print_status("#{target} - #{finding[:note]}") if finding[:note]
      report_vulnerability(ip, finding)
    when 'PATCHED', 'NOT-AFFECTED-SAAS', 'NOT-AFFECTED-NO-CAS', 'NOT-AFFECTED-NOT-GLOBALPROTECT'
      print_status("#{target} - Status: NOT VULNERABLE (#{finding[:verdict]})")
      print_status("#{target} - #{finding[:note]}") if finding[:note]
    else
      print_warning("#{target} - Status: UNDETERMINED (#{finding[:verdict]})")
      print_warning("#{target} - #{finding[:error]}") if finding[:error]
      print_status("#{target} - #{finding[:note]}") if finding[:note]
    end
  rescue ::Rex::ConnectionError, ::Timeout::Error, ::EOFError => e
    print_error("#{target_label(ip)} - Status: UNDETERMINED (network error: #{e.class}: #{e.message})")
  rescue ::StandardError => e
    print_error("#{target_label(ip)} - Status: UNDETERMINED (module error: #{e.class}: #{e.message})")
  end

  def target_label(ip)
    "#{ip}:#{datastore['RPORT']}"
  end

  def scan_target
    res = fetch_prelogin
    return error_finding('UNDETERMINED-ERROR', 'No HTTP response received') unless res

    body = res.body.to_s

    if body.include?('GlobalProtect portal does not exist')
      return {
        verdict: 'NOT-AFFECTED-NOT-GLOBALPROTECT',
        cas_enabled: 'No',
        panos_version: nil,
        note: 'Response indicates this listener is not a GlobalProtect portal.'
      }
    end

    if body.include?('Valid client certificate is required')
      return {
        verdict: 'UNDETERMINED-MTLS-GATED',
        cas_enabled: 'Unknown',
        panos_version: nil,
        note: 'mTLS gate hides the authentication profile configuration.'
      }
    end

    if body.include?('CAS is not supported by the client')
      return {
        verdict: 'UNDETERMINED-VERSION-GATED',
        cas_enabled: 'Yes',
        panos_version: nil,
        note: 'CAS is attached but the probe was User-Agent/client-version gated.'
      }
    end

    cas_auth_value = body[%r{<cas-auth>([^<]*)</cas-auth>}i, 1]
    unless cas_auth_value == 'yes'
      return {
        verdict: 'NOT-AFFECTED-NO-CAS',
        cas_enabled: 'No',
        panos_version: nil,
        note: 'prelogin response did not contain <cas-auth>yes</cas-auth>.'
      }
    end

    claims = decode_token_from_prelogin(body)
    unless claims
      return error_finding('UNDETERMINED-ERROR', 'cas-auth=yes but Token decode from prelogin response failed', 'Yes')
    end

    panos_version = claims['PanOSversion']
    verdict = advisory_verdict_for_version(panos_version.to_s)

    if verdict == 'ERROR'
      return error_finding(
        'UNDETERMINED-ERROR',
        "PanOSversion=#{panos_version.inspect} could not be parsed against advisory matrix",
        'Yes',
        panos_version
      )
    end

    note = case verdict
           when 'VULNERABLE'
             "#{panos_version} is below the advisory patched hotfix for this base."
           when 'PATCHED'
             "#{panos_version} is at or above the advisory patched hotfix for this base."
           when 'NOT-AFFECTED-SAAS'
             '.saas builds are not affected per advisory logic.'
           end

    {
      verdict: verdict,
      cas_enabled: 'Yes',
      panos_version: panos_version,
      note: note
    }
  end

  def fetch_prelogin
    last_res = nil
    attempts = datastore['RETRIES'].to_i + 1

    attempts.times do |attempt|
      res = send_request_cgi(
        {
          'method' => 'GET',
          'uri' => normalize_uri(datastore['TARGETURI']),
          'headers' => {
            'User-Agent' => datastore['USERAGENT']
          }
        },
        datastore['TIMEOUT'].to_i
      )

      return res if res && res.code != 503

      last_res = res
      Rex.sleep([attempt, 4].min) if attempt < attempts - 1
    rescue ::Rex::ConnectionError, ::Timeout::Error, ::EOFError
      Rex.sleep([attempt, 4].min) if attempt < attempts - 1
      raise if attempt == attempts - 1
    end

    last_res
  end

  def decode_token_from_prelogin(body)
    saml_request = body[%r{<saml-request>([^<]+)</saml-request>}i, 1]
    return nil unless saml_request

    html_form = Rex::Text.decode_base64(saml_request.strip).to_s
    token = html_form[/name="Token"\s+value="([^"]+)"/, 1]
    return nil unless token

    parts = token.split('.')
    return nil unless parts.length == 3

    payload_json = base64url_decode(parts[1])
    JSON.parse(payload_json)
  rescue ::StandardError
    nil
  end

  def base64url_decode(value)
    padded = value + ('=' * ((4 - value.length % 4) % 4))
    Rex::Text.decode_base64(padded.tr('-_', '+/'))
  end

  def advisory_verdict_for_version(panos_version)
    return 'ERROR' if panos_version.empty?
    return 'NOT-AFFECTED-SAAS' if panos_version.include?('.saas')

    match = panos_version.match(/^(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?$/)
    return 'ERROR' unless match

    maj = match[1].to_i
    min = match[2].to_i
    pat = match[3].to_i
    hf = match[4] ? match[4].to_i : 0

    return 'PATCHED' if UNAFFECTED_TRAINS.include?([maj, min])

    floor = ADVISORY_BASE_FLOOR[[maj, min]]
    return 'PATCHED' if floor && pat >= floor

    cutoff = ADVISORY_PATCHED_HOTFIX[[maj, min, pat]]
    return hf >= cutoff ? 'PATCHED' : 'VULNERABLE' if cutoff

    return 'VULNERABLE' if [[10, 2], [11, 1], [11, 2], [12, 1]].include?([maj, min])

    'PATCHED'
  end

  def error_finding(verdict, error, cas_enabled = 'Unknown', panos_version = nil)
    {
      verdict: verdict,
      cas_enabled: cas_enabled,
      panos_version: panos_version,
      error: error
    }
  end

  def report_vulnerability(ip, finding)
    report_vuln(
      host: ip,
      port: datastore['RPORT'],
      proto: 'tcp',
      name: 'PAN-OS GlobalProtect CAS CVE-2026-0265',
      refs: references,
      info: "CAS enabled: #{finding[:cas_enabled]}, PAN-OS version: #{finding[:panos_version]}, verdict: #{finding[:verdict]}"
    )
  end
end
