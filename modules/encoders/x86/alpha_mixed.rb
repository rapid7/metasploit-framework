##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


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
			'License'          => BSD_LICENSE,
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
		reg = datastore['BufferRegister']
		off = (datastore['BufferOffset'] || 0).to_i
		buf = ''
		
		# We need to create a GetEIP stub for the exploit
		if (not reg)
			res = Rex::Arch::X86.geteip_fpu(state.badchars)
			if (not res)
				raise RuntimeError, "Unable to generate geteip code"
			end
			buf, reg, off = res
		end

		buf + Rex::Encoder::Alpha2::AlphaMixed::gen_decoder(reg, off)
	end

	#
	# Encodes a one byte block with the current index of the length of the
	# payload.
	#
	def encode_block(state, block)
		Rex::Encoder::Alpha2::AlphaMixed::encode_byte(block.unpack('C')[0], state.badchars)
	end

	#
	# Tack on our terminator
	#
	def encode_end(state)
		state.encoded += Rex::Encoder::Alpha2::AlphaMixed::add_terminator()
	end
end

end end end
