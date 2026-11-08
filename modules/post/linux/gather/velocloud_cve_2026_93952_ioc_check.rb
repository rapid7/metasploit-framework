##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Arista VeloCloud Orchestrator CVE-2026-93952 Compromise Check',
        'Description' => %q{
          This module checks an on-premises Arista (formerly VMware) VeloCloud
          Orchestrator (VCO) host for the published host-side indicators of
          compromise (IOCs) associated with exploitation of CVE-2026-93952, a
          critical improper input validation flaw (CWE-20), scored by Arista
          PSIRT as CVSS v3.1 10.0 and CVSS v4.0 9.5.

          This is a defensive, read-only forensic check intended to be run by an
          operator on a VCO host they administer. It does not exploit anything.
          It inspects the file system for known malicious artifacts, computes the
          MD5 of a known implant binary to compare against the published hash,
          looks for the malicious systemd service unit, and scans available nginx
          access logs for the reported attacker IP addresses.

          A match indicates the host should be treated as compromised and taken
          through the vendor's incident response guidance. The absence of matches
          is not proof the host is clean; attacker artifacts may differ from the
          published set.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'enp7s0d' # Metasploit module
        ],
        'Platform' => [ 'linux', 'unix' ],
        'SessionTypes' => %w[shell meterpreter],
        'References' => [
          [ 'CVE', '2026-93952' ],
          [ 'URL', 'https://www.arista.com/en/support/advisories-notices/security-advisory/24765-security-advisory-0183' ],
          [ 'URL', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-93952' ],
          [ 'URL', 'https://github.com/rapid7/metasploit-framework/issues/21940' ]
        ],
        'DisclosureDate' => '2026-09-22',
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  # Published host-side IOCs for CVE-2026-93952 exploitation.
  # Source: Arista advisory / public reporting (see References).
  IOC_FILES = [
    '/usr/local/sbin/.vcnode.js',
    '/usr/local/sbin/vc-sysmond'
  ].freeze

  # Known-bad MD5 of the vc-sysmond implant.
  IOC_HASHES = {
    '/usr/local/sbin/vc-sysmond' => 'dc78e206eaeadec59fc5801fe4556bd0'
  }.freeze

  # Candidate locations for the malicious systemd unit.
  IOC_SERVICE_PATHS = [
    '/etc/systemd/system/vc-sysmon.service',
    '/lib/systemd/system/vc-sysmon.service',
    '/usr/lib/systemd/system/vc-sysmon.service'
  ].freeze

  # Attacker IP addresses reported in the advisory.
  IOC_IPS = [
    '142.93.149.77',
    '104.248.126.159'
  ].freeze

  # Attacker-request HTTP header reported in the advisory. Matched case-
  # insensitively in available nginx access logs; the appearance of this
  # header is itself an indicator even when the client IP has rotated.
  IOC_LOG_HEADER = 'x-vc-opt'

  # Common nginx access log locations to scan.
  NGINX_LOG_PATHS = [
    '/var/log/nginx/access.log',
    '/var/log/nginx/portal_access.log',
    '/var/log/velocloud/nginx/access.log'
  ].freeze

  def run
    print_status('Checking host for CVE-2026-93952 indicators of compromise')
    @probe_errors = 0
    findings = []

    findings.concat(check_files)
    findings.concat(check_hashes)
    findings.concat(check_service)
    findings.concat(check_logs)

    if findings.empty?
      print_status('No published CVE-2026-93952 indicators of compromise were found')
      print_status('Note: a clean result is not proof the host is uncompromised')
      warn_on_partial_result
      return
    end

    print_warning("#{findings.length} indicator(s) of compromise found - treat this host as compromised")
    findings.each { |f| print_bad("  #{f}") }
    warn_on_partial_result

    # Indicators of compromise are evidence of past attacker activity, not of
    # the host being vulnerable to CVE-2026-93952 (an exposed host may also be
    # patched; a compromised host may already be patched). Record the findings
    # as a note on the session host and let the operator decide on disposition,
    # following the vendor's incident response guidance.
    report_note(
      host: session.session_host,
      type: 'velocloud.cve_2026_93952.ioc',
      data: { indicators: findings },
      update: :unique_data
    )
  end

  def check_files
    IOC_FILES.select { |path| safe_file?(path) }.map do |path|
      print_bad("Malicious artifact present: #{path}")
      "file:#{path}"
    end
  end

  def check_hashes
    results = []
    IOC_HASHES.each do |path, known_bad|
      next unless safe_file?(path)

      actual = begin
        file_remote_digestmd5(path)
      rescue StandardError => e
        print_warning("Could not calculate MD5 for #{path}; hash check incomplete: #{e.message}")
        elog("Could not hash #{path}", error: e)
        @probe_errors += 1
        nil
      end

      next if actual.nil?

      if actual.casecmp?(known_bad)
        print_bad("#{path} matches known implant MD5 #{known_bad}")
        results << "hash:#{path}=#{known_bad}"
      else
        vprint_status("#{path} present but MD5 #{actual} does not match published hash")
      end
    end
    results
  end

  def check_service
    IOC_SERVICE_PATHS.select { |path| safe_file?(path) }.map do |path|
      print_bad("Malicious systemd unit present: #{path}")
      "service:#{path}"
    end
  end

  def check_logs
    results = []
    NGINX_LOG_PATHS.each do |log|
      next unless safe_file?(log)

      # A log the session user cannot read makes every grep return empty
      # output. Without this probe, an unreadable log would silently register
      # as "no hit" and the run would report a clean result. Treat unreadable
      # logs as probe failures so warn_on_partial_result surfaces the gap.
      unless readable_log?(log)
        print_warning("Cannot read #{log}; log check incomplete")
        @probe_errors += 1
        next
      end

      IOC_IPS.each do |ip|
        # Anchor to the client-address field so a request for /<ip> or a
        # matching Referer / User-Agent does not false-positive. nginx's
        # default combined log format places $remote_addr as the first
        # whitespace-separated field.
        hit = cmd_exec("grep -E -m1 '^#{Regexp.escape(ip)}[[:space:]]' #{log} 2>/dev/null")
        next if hit.nil? || hit.strip.empty?

        print_bad("Attacker IP #{ip} found in #{log}")
        results << "log:#{log}:#{ip}"
      end

      # Bounded case-insensitive scan for the attacker-request header. It is
      # only emitted in access logs when the log format includes
      # $http_x_vc_opt, so an absent result on an unknown log format is not
      # conclusive and is treated as such.
      header_hit = cmd_exec("grep -i -F -m1 #{IOC_LOG_HEADER} #{log} 2>/dev/null")
      next if header_hit.nil? || header_hit.strip.empty?

      print_bad("Attacker-request header '#{IOC_LOG_HEADER}' found in #{log}")
      results << "log:#{log}:header=#{IOC_LOG_HEADER}"
    end
    results
  end

  # Confirm the session can actually read the log file. file? only reports
  # existence, which is not enough on hosts where logs are root-only and the
  # session is unprivileged.
  def readable_log?(log)
    cmd_exec("test -r #{log} && echo readable").to_s.include?('readable')
  rescue StandardError => e
    elog("Could not check readability of #{log}", error: e)
    false
  end

  # Wrap the existence check so a single failing probe never aborts the run.
  # Probe failures are counted so the operator can see the result was partial.
  def safe_file?(path)
    file?(path)
  rescue StandardError => e
    print_warning("Could not check #{path}; the result may be incomplete: #{e.message}")
    elog("Could not check #{path}", error: e)
    @probe_errors += 1
    false
  end

  def warn_on_partial_result
    return if @probe_errors.to_i.zero?

    print_warning("#{@probe_errors} probe(s) failed; this result is incomplete")
  end
end
