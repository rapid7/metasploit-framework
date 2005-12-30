require 'msf/core'

module Msf
module Encoders
module X86

class Countdown < Msf::Encoder::Xor

	def initialize
		super(
			'Name'             => 'Single-byte XOR Countdown Encoder',
			'Version'          => '$Revision$',
			'Description'      => %q{
				This encoder uses the length of the payload as a position-dependent
				encoder key to produce a small decoder stub.
			},
			'Author'           => 'vlad902',
			'Arch'             => ARCH_X86,
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
		decoder = 
			Rex::Arch::X86.set(
				Rex::Arch::X86::ECX,
				state.buf.length - 1,
				state.badchars) +
			"\xe8\xff\xff\xff" +		# call $+4
			"\xff\xc1" +			# inc ecx
			"\x5e" +			# pop esi
			"\x30\x4c\x0e\x07" +		# xor_loop: xor [esi + ecx + 0x07], cl
			"\xe2\xfa"			# loop xor_loop

		# Initialize the state context to 1
		state.context = 1

		return decoder
	end

	#
	# Encodes a one byte block with the current index of the length of the
	# payload.
	#
	def encode_block(state, block)
		state.context += 1
		
		[ block.unpack('C')[0] ^ (state.context - 1) ].pack('C')
	end

end

end end end
