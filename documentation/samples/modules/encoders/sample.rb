module Msf
module Encoders

###
#
# This sample illustrates a very basic encoder that simply returns the block
# that it's passed.
#
###
class Sample < Msf::Encoder

	def initialize
		super(
			'Name'             => 'Sample encoder',
			'Version'          => '$Revision$',
			'Description'      => %q{
				Sample encoder that just returns the block it's passed
				when encoding occurs.
			},
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

end 
end
