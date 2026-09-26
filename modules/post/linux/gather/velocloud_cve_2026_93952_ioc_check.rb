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

  # Common nginx access log locations to scan for the attacker IPs.
  NGINX_LOG_PATHS = [
    '/var/log/nginx/access.log',
    '/var/log/nginx/portal_access.log',
    '/var/log/velocloud/nginx/access.log'
  ].freeze

  def run
    print_status('Checking host for CVE-2026-93952 indicators of compromise')
    findings = []

    findings.concat(check_files)
    findings.concat(check_hashes)
    findings.concat(check_service)
    findings.concat(check_logs)

    if findings.empty?
      print_status('No published CVE-2026-93952 indicators of compromise were found')
      print_status('Note: a clean result is not proof the host is uncompromised')
      return
    end

    print_warning("#{findings.length} indicator(s) of compromise found - treat this host as compromised")
    findings.each { |f| print_bad("  #{f}") }

    report_vuln(
      host: session.session_host,
      name: name,
      info: "CVE-2026-93952 host-side IOCs detected: #{findings.join('; ')}",
      refs: references
    )

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
        vprint_error("Could not hash #{path}: #{e.message}")
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

      IOC_IPS.each do |ip|
        # Bounded, read-only grep; -F fixed-string, -m1 stop at first hit.
        hit = cmd_exec("grep -F -m1 #{ip} #{log} 2>/dev/null")
        next if hit.nil? || hit.strip.empty?

        print_bad("Attacker IP #{ip} found in #{log}")
        results << "log:#{log}:#{ip}"
      end
    end
    results
  end

  # Wrap the existence check so a single failing probe never aborts the run.
  def safe_file?(path)
    file?(path)
  rescue StandardError => e
    vprint_error("Could not check #{path}: #{e.message}")
    false
  end
end
