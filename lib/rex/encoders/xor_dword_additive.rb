#!/usr/bin/ruby

require 'Rex/Encoder/Xor/DWordAdditive'

#
# Jmp/Call DWord Additive Feedback Encoder
# Author: skape
# Arch:   x86
#

module Rex
module Encoders

class XorDWordAdditive < Rex::Encoder::Xor::DWordAdditive
	module Backend

		def _unencoded_transform(data)
			# pad to a dword boundary so we can append our key aligned
			data = data + ("\x00" * ((4 - data.length & 3) & 3)) + "\x00\x00\x00\x00"
		end

		def _prepend
			"\xfc"                + # cld
			"\xbb" + key          + # mov ebx, key
			"\xeb\x0c"            + # jmp short 0x14
			"\x5e"                + # pop esi
			"\x56"                + # push esi
			"\x31\x1e"            + # xor [esi], ebx
			"\xad"                + # lodsd
			"\x01\xc3"            + # add ebx, eax
			"\x85\xc0"            + # test eax, eax
			"\x75\xf7"            + # jnz 0xa
			"\xc3"                + # ret
			"\xe8\xef\xff\xff\xff"  # call 0x8
		end
	end

	include Backend
end

end end
