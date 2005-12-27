require 'msf/core'
require 'msf/core/handler/find_shell'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Cmd
module Unix

module Interact

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Unix Command, Interact with established connection',
			'Version'       => '$Revision$',
			'Description'   => 'Interacts with a shell on an established TCP connection',
			'Author'        => 'hdm',
			'Platform'      => 'unix',
			'Arch'          => ARCH_CMD,
			'Handler'       => Msf::Handler::FindShell,
			'Session'       => Msf::Sessions::CommandShell,
			'PayloadType'   => 'cmd interact',
			'Payload'       =>
				{
					'Offsets' => { },
					'Payload' => ''
				}
			))
	end

end

end end end end end
