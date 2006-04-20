require 'msf/core'
require 'rex/encoder/nonalpha'

module Msf
module Encoders
module X86

class NonAlpha < Msf::Encoder::NonAlpha

	Rank = LowRanking

	def initialize
		super(
			'Name'             => "Non-Alpha Encoder",
			'Version'          => '$Revision$',
			'Description'      => %q{
				Encodes payloads a non-alpha based bytes. This allows
                payloads to bypass both toupper() and tolower() calls,
                but will fail isalpha().
			},
			'Author'           => [ 'pusscat'],
			'Arch'             => ARCH_X86,
			'License'          => MSF_LICENSE,
			'EncoderType'      => Msf::Encoder::Type::NonAlpha,
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
        state.key                   = ""
        state.decoder_key_size      = 0
		Rex::Encoder::NonAlpha::gen_decoder()
	end

	#
	# Encodes a one byte block with the current index of the length of the
	# payload.
	#
	def encode_block(state, block)
		Rex::Encoder::NonAlpha::encode_byte(block.unpack('C')[0], state.key, state.decoder_key_size)
	end

	#
	# Fix stuff, and add the table :)
	#
	def encode_end(state)
	    state.encoded.gsub!(/A/, state.decoder_key_size.chr)
	    state.encoded.gsub!(/B/, (state.decoder_key_size+5).chr)
        state.encoded[0x1E, 0] = state.key
    end
end

end end end
