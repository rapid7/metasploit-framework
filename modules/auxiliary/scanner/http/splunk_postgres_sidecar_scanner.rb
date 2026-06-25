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

  # The recovery endpoint, reached through the Splunk Web __raw proxy. A
  # non-Splunk (Basic) credential is enough to pass an affected server's
  # (absent) authorization check; "dag:" is the credential used by the public
  # detection artifact.
  def probe
    send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, datastore['LOCALE'], 'splunkd', '__raw', 'v1', 'postgres', 'recovery', 'backup'),
        'headers' => { 'Authorization' => 'Basic ZGFnOg==' }
      }
    )
  end

  def run_host(_ip)
    res = probe
    unless res
      vprint_error("#{peer} - No response from the Splunk Web recovery endpoint")
      return
    end

    if res.code == 400 && res.body.to_s.include?('Failed to decode request')
      print_good("#{peer} - Vulnerable: the PostgreSQL sidecar recovery endpoint accepted an unauthenticated request (CVE-2026-20253)")
      report_vuln(
        host: rhost,
        port: rport,
        name: name,
        info: 'Unauthenticated access to /splunkd/__raw/v1/postgres/recovery/backup (HTTP 400 "Failed to decode request")',
        refs: references
      )
    elsif res.code == 401 && res.body.to_s.include?('Splunk token')
      print_status("#{peer} - Not vulnerable: the recovery endpoint requires a Splunk token (patched)")
    else
      vprint_status("#{peer} - PostgreSQL sidecar recovery endpoint not detected (HTTP #{res.code}); likely not installed or not Splunk Web")
    end
  end
end
