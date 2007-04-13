module Msf
module Encoders

class BlackHatEncoder < Msf::Encoder

	def initialize
		super(
			'Name'             => 'BlackHat Example Encoder',
			'Version'          => '$Revision: 3154 $',
			'Description'      => %q{
				Sample encoder that just returns the block it's passed
				when encoding occurs.
			},
			'Author'           => 'skape',
			'Arch'             => ARCH_ALL)
	end

	def encode_block(state, buf)
		buf
	end

end ;end ;end
