# frozen_string_literal: true

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
        'Name' => 'Splunk Enterprise PostgreSQL Sidecar Unauthenticated File Operation Scanner',
        'Description' => %q{
          This module detects Splunk Enterprise servers affected by
          CVE-2026-20253. Splunk Enterprise 10.x ships a PostgreSQL "sidecar"
          service (used by Edge Processor, OpAmp, and SPL2 data pipelines) whose
          recovery endpoint, reachable through Splunk Web at
          /<locale>/splunkd/__raw/v1/postgres/recovery/backup, performs no
          authorization. An unauthenticated, network-adjacent attacker can invoke
          arbitrary file create/truncate operations, which has been shown to chain
          to remote code execution via PostgreSQL's lo_export.

          Affected versions are 10.0.0 through 10.0.6 (fixed in 10.0.7) and 10.2.0
          through 10.2.3 (fixed in 10.2.4); 10.4.0 and later are not affected.
          Splunk Cloud Platform does not use Postgres sidecars and is not affected.

          The module sends a benign request that mirrors the watchTowr detection
          artifact: a POST to the recovery endpoint carrying a non-Splunk
          (Basic) Authorization header. An affected build accepts the request past
          authorization and fails decoding the (empty) body with HTTP 400
          "Failed to decode request"; a patched build rejects the Basic header
          with HTTP 401 "Authorization header must use Splunk token". The module
          does not create, truncate, or read any file.
        },
        'Author' => [
          'Piotr Bazydlo', # CVE-2026-20253 detection artifact (watchTowr)
          'Kenneth LaCroix' # Metasploit module
        ],
        'References' => [
          ['CVE', '2026-20253'],
          ['URL', 'https://advisory.splunk.com/advisories/SVD-2026-0603'],
          ['URL', 'https://github.com/watchtowrlabs/watchTowr-vs-Splunk-CVE-2026-20253']
        ],
        'DisclosureDate' => '2026-06-10',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DefaultOptions' => { 'RPORT' => 8000, 'SSL' => false }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to Splunk Web', '/']),
        OptString.new('LOCALE', [true, 'The Splunk Web locale segment present in URLs', 'en-US'])
      ]
    )
  end

  # POST to the recovery endpoint, reached through the Splunk Web __raw proxy.
  # Pass the Basic credential ("dag:", the value used by the public detection
  # artifact) to reach the recovery endpoint past an affected server's (absent)
  # authorization check; an empty header set is the unauthenticated control.
  def probe(extra_headers = {})
    send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, datastore['LOCALE'], 'splunkd', '__raw', 'v1', 'postgres', 'recovery', 'backup'),
        'headers' => extra_headers
      }
    )
  end

  # Confirm the target is Splunk Web before interpreting the recovery-endpoint
  # behaviour, and register it as a service.
  def fingerprint_splunk_web
    res = send_request_cgi('method' => 'GET', 'uri' => normalize_uri(target_uri.path, datastore['LOCALE'], 'account', 'login'))
    return false unless res
    return false unless res.headers['Server'].to_s.include?('Splunkd') ||
                        res.get_cookies.to_s.include?('splunkweb') ||
                        res.body.to_s.include?('Splunk')

    report_service(host: rhost, port: rport, proto: 'tcp', name: (ssl ? 'https' : 'http'), info: 'Splunk Web')
    true
  end

  def run_host(_ip)
    fingerprint_splunk_web

    # Control: with no Authorization header the Splunk Web __raw proxy returns
    # HTTP 401 on both affected and patched builds, so a bare 400 is not by
    # itself a bypass signal.
    control = probe
    # Bypass: a non-Splunk Basic credential passes an affected server's (absent)
    # authorization check and reaches the recovery endpoint, which fails to
    # decode the empty body (HTTP 400 "Failed to decode request").
    bypass = probe('Authorization' => 'Basic ZGFnOg==')

    unless control && bypass
      vprint_error("#{peer} - No response from the Splunk Web recovery endpoint")
      return
    end

    if control.code == 401 && bypass.code == 400 && bypass.body.to_s.include?('Failed to decode request')
      print_good("#{peer} - Vulnerable: a non-Splunk Basic credential bypassed authorization on the PostgreSQL sidecar recovery endpoint (CVE-2026-20253)")
      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        info: 'Auth bypass on /splunkd/__raw/v1/postgres/recovery/backup: no-auth -> HTTP 401, Basic-auth -> HTTP 400 "Failed to decode request"',
        refs: references
      )
    elsif bypass.code == 401 && bypass.body.to_s.include?('Splunk token')
      print_status("#{peer} - Not vulnerable: the recovery endpoint requires a Splunk token (patched)")
    else
      vprint_status("#{peer} - Auth-bypass signature not present (control HTTP #{control.code}, bypass HTTP #{bypass.code}); not confirmed vulnerable")
    end
  end
end
