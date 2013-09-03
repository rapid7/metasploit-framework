#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class UnicodeUpper < Generic
	def self.default_accepted_chars ; ('B' .. 'Z').to_a + ('0' .. '9').to_a ; end

	def self.gen_second(block, base)
		# unicode uses additive encoding
		(block - base)
	end

	def self.gen_decoder_prefix(reg, offset)
		if (offset > 6)
			raise "Critical: Offset is greater than 6"
		end

		# offset untested for unicode :(
		if (offset <= 4)
			nop = 'CP' * offset
			mod = 'IA' * (4 - offset) + nop    # dec ecx,,, push ecx, pop edx
		else
			mod = 'AA' * (offset - 4)          # inc ecx
			nop = 'CP' * (4 - mod.length)
			mod += nop
		end

		regprefix = {                      # nops ignored below
			'EAX'   => 'PPYA' + mod,        # push eax, pop ecx
			'ECX'   =>  mod + '4444',       # dec ecx
			'EDX'   => 'RRYA' + mod,        # push edx, pop ecx
			'EBX'   => 'SSYA' + mod,        # push ebx, pop ecx
			'ESP'   => 'TUYA' + mod,        # push esp, pop ecx
			'EBP'   => 'UUYA' + mod,        # push ebp, pop ecx
			'ESI'   => 'VVYA' + mod,        # push esi, pop ecx
			'EDI'   => 'WWYA' + mod,        # push edi, pop edi
			'[ESP]' => 'YA' + mod + '44',   #
			'[ESP+4]' => 'YUYA' + mod,      #
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
			"PU" +                  # push eax, NOP
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
