##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex/encoder/alpha2/unicode_upper'


class Metasploit3 < Msf::Encoder::Alphanum

	Rank = ManualRanking

	def initialize
		super(
			'Name'             => "Alpha2 Alphanumeric Unicode Uppercase Encoder",
			'Description'      => %q{
				Encodes payload as unicode-safe uppercase text.  This encoder uses
				SkyLined's Alpha2 encoding suite.
			},
			'Author'           => [ 'pusscat', 'skylined' ],
			'Arch'             => ARCH_X86,
			'License'          => BSD_LICENSE,
			'EncoderType'      => Msf::Encoder::Type::AlphanumUnicodeUpper,
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
		reg    = datastore['BufferRegister']
		offset = datastore['BufferOffset'].to_i || 0
		if (not reg)
			raise RuntimeError, "Need BufferRegister"
		end
		Rex::Encoder::Alpha2::UnicodeUpper::gen_decoder(reg, offset)
	end

	#
	# Encodes a one byte block with the current index of the length of the
	# payload.
	#
	def encode_block(state, block)
		Rex::Encoder::Alpha2::UnicodeUpper::encode_byte(block.unpack('C')[0], state.badchars)
	end

	#
	# Tack on our terminator
	#
	def encode_end(state)
		state.encoded += Rex::Encoder::Alpha2::UnicodeUpper::add_terminator()
	end

	#
	# Returns the unicode version of the supplied buffer.
	#
	def to_native(buffer)
		Rex::Text.to_unicode(buffer)
	end

end
