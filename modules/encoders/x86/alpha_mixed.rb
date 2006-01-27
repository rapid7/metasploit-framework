require 'msf/core'
require 'rex/encoder/alpha2/alpha_mixed'

module Msf
module Encoders
module X86

class AlphaMixed < Msf::Encoder::Alphanum

	Rank = LowRanking

	def initialize
		super(
			'Name'             => "Alpha2 Alphanumeric Mixedcase Encoder",
			'Version'          => '$Revision$',
			'Description'      => %q{
				Encodes payloads as alphanumeric mixedcase text.  This encoder uses
				SkyLined's Alpha2 encoding suite.
			},
			'Author'           => [ 'pusscat', 'skylined' ],
			'Arch'             => ARCH_X86,
			'License'          => MSF_LICENSE,
			'EncoderType'      => Msf::Encoder::Type::AlphanumMixed,
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
		reg    = datastore['BufferRegister']    || 'EAX' 
		offset = datastore['BufferOffset'].to_i || 0

		Rex::Encoder::Alpha2::AlphaMixed::gen_decoder(reg, offset)
	end

	#
	# Encodes a one byte block with the current index of the length of the
	# payload.
	#
	def encode_block(state, block)
		Rex::Encoder::Alpha2::AlphaMixed::encode_byte(block.unpack('C')[0], datastore['BadChars'])
	end

	#
	# Tack on our terminator
	#
	def encode_end(state)
		state.encoded += Rex::Encoder::Alpha2::AlphaMixed::add_terminator()
	end
end

end end end
