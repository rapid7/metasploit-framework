##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

###
#
# This sample illustrates a very basic encoder that simply returns the block
# that it's passed.
#
###
class Metasploit4 < Msf::Encoder

	def initialize
		super(
			'Name'             => 'Sample Encoder',
			'Description'      => %q{
				Sample encoder that just returns the block it's passed
				when encoding occurs.
			},
			'License'          => MSF_LICENSE,
			'Author'           => 'skape',
			'Arch'             => ARCH_ALL)
	end

	#
	# Returns the unmodified buffer to the caller.
	#
	def encode_block(state, buf)
		buf
	end

end
