#!/usr/bin/env ruby

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class UnicodeUpper < Generic
	@@accepted_chars = ('B' .. 'Z').to_a + ('0' .. '9').to_a
   
	def self.gen_base(max)
		max = max / 0x10
		(rand(max) * 0x10)
	end

	def self.gen_second(block, base)
		# unicode uses additive encoding
		(block - base)
	end

	def self.gen_decoder_prefix(reg, offset)
		if (offset > 4)
			raise "Critical: Offset is greater than 4"
		end

		# offset untested for unicode :(
		nop = 'CP' * offset
		dec = 'IA' * (4 - offset) + nop    # dec ecx,,, push ecx, pop edx

		regprefix = {                      # nops ignored below
			'EAX'   => 'PPYA' + dec,        # push eax, pop ecx
			'ECX'   =>  dec + '4444',       # dec ecx
			'EDX'   => 'RRYA' + dec,        # push edx, pop ecx
			'EBX'   => 'SSYA' + dec,        # push ebx, pop ecx
			'ESP'   => 'TUYA' + dec,        # push esp, pop ecx
			'EBP'   => 'UUYA' + dec,        # push ebp, pop ecx
			'ESI'   => 'VVYA' + dec,        # push esi, pop ecx
			'EDI'   => 'WWYA' + dec,        # push edi, pop edi
			'[ESP]' => 'YA' + dec + '44',   #
			'[ESP+4]' => 'YUYA' + dec,      # 
		}

		return regprefix[reg]
	end

	def self.gen_decoder(reg, offset)
		decoder =
			gen_decoder_prefix(reg, offset) +
			"QA" +                  # push ecx, NOP
			"TA" +                  # push esp, NOP
			"XA" +                  # pop eax, NOP
			"ZA" +                  # pop edx, NOP
			"PA" +                  # push eax, NOP
			"3" +                   # xor eax, [eax]
			"QA" +                  # push ecx, NOP
			"DA" +                  # inc esp, NOP
			"ZA" +                  # pop edx, NOP
			"BA" +                  # inc edx, NOP
			"RA" +                  # push edx, NOP
			"LA" +                  # dec esp, NOP
			"YA" +                  # pop ecx, NOP
			"IA" +                  # dec ecx, NOP
			"QA" +                  # push ecx, NOP
			"IA" +                  # dec ecx, NOP
			"QA" +                  # push ecx, NOP
			"PA" +                  # push eax, NOP
			"5AAA" +                # xor eax, 41004100 - NOP
			"PA" +                  # push eax, NOP
			"Z" +                   # pop edx
			"1A" +                  # add [ecx], dh - NOP
			"I" +                   # dec ecx
			"1A" +                  # add [ecx], dh - NOP
			"IA" +                  # dec ecx, NOP
			"IA" +                  # dec ecx, NOP
			"J" +                   # dec edx
			"1" +                   # add [ecx], dh
			"1A" +                  # add [ecx], dh - NOP
			"IA" +                  # dec ecx, NOP
			"IA" +                  # dec ecx, NOP
			"XA" +                  # pop eax, NOP
			"58AA" +                # xor eax, 41003800 - NOP
			"PA" +                  # push eax, NOP
			"ZA" +                  # pop edx, NOP
			"BA" +                  # inc edx, NOP
			"B" +                   # inc edx
			"Q" +                   # add [ecx], dl
			"I" +                   # dec ecx
			"1A" +                  # add [ecx], dh - NOP
			"I" +                   # dec ecx
			"Q" +                   # add [ecx], dl
			"IA" +                  # dec ecx, NOP
			"I" +                   # dec ecx
			"Q" +                   # add [ecx], dl
			"I" +                   # dec ecx
			"1" +                   # add [ecx], dh
			"1" +                   # add [ecx], dh
			"1" +                   # add [ecx], dh
			"1A" +                  # add [ecx], dh - NOP
			"IA" +                  # dec ecx, NOP
			"J" +                   # dec edx
			"Q" +                   # add [ecx], dl
			"I" +                   # dec edx
			"1A" +                  # add [ecx], dh - NOP
			"YA" +                  # pop ecx, NOP
			"ZB" +                  # pop edx, NOP
			"AB" +                  # inc ecx, NOP      <-------
			"AB" +                  # inc ecx, NOP              |
			"AB" +                  # inc ecx, NOP              |
			"AB" +                  # inc ecx, NOP              |
			"30" +                  # imul eax, [ecx], 10 *     |
			"A" +                   # add al, [ecx+2] *         |
			"P" +                   # mov [edx], al *           |
			"B" +                   # inc edx                   |
			"9" +                   # cmp [ecx], 41 *           |
			"4" +                   # jnz   --------------------
			"4JB"

		return decoder
	end

end end end end
