#!/usr/bin/env ruby

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class AlphaMixed < Generic

	def self.gen_decoder_prefix(reg, offset)
		if (offset > 16)
			raise "Critical: Offset is greater than 16"
		end

		# use inc ebx as a nop here so we still pad correctly
		nop = 'C' * offset
		dec = 'I' * (16 - offset) + nop + '7QZ'    # dec ecx,,, push ecx, pop edx

		regprefix = {
			'EAX'   => 'PY' + dec,                         # push eax, pop ecx
			'ECX'   => 'I' + dec,                          # dec ecx
			'EDX'   => 'J' * (17 - offset) + nop + '7RY',  # dec edx,,, push edx, pop ecx
			'EBX'   => 'SY' + dec,                         # push ebx, pop ecx
			'ESP'   => 'TY' + dec,                         # push esp, pop ecx
			'EBP'   => 'UY' + dec,                         # push ebp, pop ecx
			'ESI'   => 'VY' + dec,                         # push esi, pop ecx
			'EDI'   => 'WY' + dec,                         # push edi, pop ecx
		}

		return regprefix[reg]
	end

	def self.gen_decoder(reg, offset)
		decoder =
			 gen_decoder_prefix(reg, offset) +
			 "jA" +          # push 0x41
			 "X" +           # pop eax
			 "P" +           # push eax 
			 "0A0" +         # xor byte [eax+30], al
			 "A" +           # inc ecx                        <---
			 "kAAQ" +        # imul eax, [ecx+42], 51 -> 10       |
			 "2AB" +         # xor al, [ecx + 42]                 |
			 "2BB" +         # xor al, [edx + 42]                 |
			 "0BB" +         # xor [edx + 42], al                 |
			 "A" +           # inc ecx                            |
			 "B" +           # inc edx                            |
			 "X" +           # pop eax                            |
			 "P" +           # push eax                           |
			 "8AB" +         # cmp [ecx + 42], al                 |
			 "uJ" +          # jnz short -------------------------
			 "I"             # first encoded char, fixes the above J

		return decoder
	end

end end end end
