#!/usr/bin/env ruby

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class AlphaUpper < Generic
	@@accepted_chars = ('B' .. 'Z').to_a + ('0' .. '9').to_a
    
	def self.gen_decoder_prefix(reg, offset)
		if (offset > 10)
			raise "Critical: Offset is greater than 10"
		end

		# use inc ebx as a nop here so we still pad correctly
		nop = 'C' * offset
		dec = 'I' * (10 - offset) + nop + 'QZ'           # dec ecx,,, push ecx, pop edx

		regprefix = {
			'EAX'   => 'PY' + dec,                        # push eax, pop ecx
			'ECX'   => 'I' + dec,                         # dec ecx
			'EDX'   => 'J' * (11 - offset) + nop + 'RY',  # dec edx,,, push edx, pop ecx
			'EBX'   => 'SY' + dec,                        # push ebx, pop ecx
			'ESP'   => 'TY' + dec,                        # push esp, pop ecx
			'EBP'   => 'UY' + dec,                        # push ebp, pop ecx
			'ESI'   => 'VY' + dec,                        # push esi, pop ecx
			'EDI'   => 'WY' + dec,                        # push edi, pop edi
		}

		return regprefix[reg]

    end

	def self.gen_decoder(reg, offset)
		decoder =
			gen_decoder_prefix(reg, offset) +
			"V" +           # push esi
			"T" +           # push esp
			"X" +           # pop eax 
			"30" +          # xor esi, [eax]
			"V" +           # push esi
			"X" +           # pop eax
			"4A" +          # xor al, 41
			"P" +           # push eax 
			"0A3" +         # xor [ecx+33], al
			"H" +           # dec eax
			"H" +           # dec eax
			"0A0" +         # xor [ecx+30], al
			"0AB" +         # xor [ecx+42], al
			"A" +           # inc ecx   <---------------
			"A" +           # inc ecx                   |
			"B" +           # inc edx                   |
			"TAAQ" +        # imul eax, [ecx+41], 10 *  | 
			"2AB" +         # xor al [ecx+42]           |
			"2BB" +         # xor al, [edx+42]          |
			"0BB" +         # xor [edx+42], al          |
			"X" +           # pop eax                   |
			"P" +           # push eax                  |
			"8AC" +         # cmp [ecx+43], al          |
			"JJ" +          # jnz * --------------------
			"I"             # first encoded char, fixes the above J

		return decoder
	end

end end end end
