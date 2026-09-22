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
          version falls within a range affected by CVE-2026-93952, a CVSS 10.0 improper
          input validation flaw (CWE-20).

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
          [ 'URL', 'https://thehackernews.com/2026/09/new-cvss-100-velocloud-orchestrator.html' ]
        ],
        'DisclosureDate' => '2026-09-22',
        'DefaultOptions' => {
          'SSL' => true,
          'RPORT' => 443
        },
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [ IOC_IN_LOGS ],
          'Reliability' => []
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

  def vulnerable?(version)
    train = version.version.take(2).join('.')

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
  # NOTE: the exact unauthenticated version signal must be validated against a
  # live VCO instance before this module is considered production-ready. The VCO
  # UI is an nginx-fronted SPA whose REST API lives under /portal/rest. Candidate
  # signals below are ordered most-to-least likely; adjust to whatever the tested
  # build actually returns and record the tested versions in the module notes.
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

  def looks_like_vco?(res)
    return false unless res

    body = res.body.to_s
    body.include?('VeloCloud') ||
      body.include?('velocloud') ||
      res.headers.to_s.include?('velocloud')
  end

  def run_host(ip)
    peer = Rex::Socket.to_authority(ip, datastore['RPORT'])
    vprint_status("#{peer} - Checking for VeloCloud Orchestrator")

    landing = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path)
    )

    unless looks_like_vco?(landing)
      vprint_error("#{peer} - VeloCloud Orchestrator not detected")
      return
    end

    version = get_version
    if version.nil?
      print_status("#{peer} - VeloCloud Orchestrator detected, but version could not be determined")
      return
    end

    print_good("#{peer} - VeloCloud Orchestrator version #{version} detected")
    report_note(
      host: ip,
      port: datastore['RPORT'],
      proto: ssl ? 'https' : 'http',
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
