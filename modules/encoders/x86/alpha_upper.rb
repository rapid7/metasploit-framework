require 'msf/core'
require 'rex/encoder/alpha2/alpha_upper'

module Msf
module Encoders
module X86

class AlphaUpper < Msf::Encoder

	def initialize
		super(
			'Name'             => "Alpha2 Alphanumeric Uppercase Encoder",
			'Version'          => '$Revision$',
			'Description'      => %q{
				Encodes payloads as alphanumeric uppercase text.  This encoder uses
				SkyLined's Alpha2 encoding suite.
            },
			'Author'           => [ 'pusscat' 'skylined' ],
			'Arch'             => ARCH_X86,
			'EncoderType'      => 'alphanum',
			'Decoder'          =>
				{
					'BlockSize' => 1,
				})
	end

	#
	# Returns the decoder stub that is adjusted for the size of the buffer
	# being encoded.
	#
	def decoder_stub(state)
		reg = 'EAX'
		offset = 0
        
		Rex::Encoder::Alpha2::AlphaUpper::gen_decoder(reg, offset)
	end

	#
	# Encodes a one byte block with the current index of the length of the
	# payload.
	#
	def encode_block(state, block)
		return Rex::Encoder::Alpha2::AlphaUpper::encode_byte(block.unpack('C')[0])        
	end

	#
	# Tack on our terminator
	#
	def encode_end(state)
		state.encoded += Rex::Encoder::Alpha2::AlphaUpper::add_terminator()
	end
end

end end end
