# -*- coding: binary -*-

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class AlphaMixed < Generic

  def self.gen_decoder_prefix(reg, offset)
    if (offset > 32)
      raise "Critical: Offset is greater than 32"
    end

    # use inc ebx as a nop here so we still pad correctly
    if (offset <= 16)
      nop = 'C' * offset
      mod = 'I' * (16 - offset) + nop + '7QZ'    # dec ecx,,, push ecx, pop edx
      edxmod = 'J' * (17 - offset)
    else
      mod = 'A' * (offset - 16)
      nop = 'C' * (16 - mod.length)
      mod << nop + '7QZ'
      edxmod = 'B' * (17 - (offset - 16))
    end
    regprefix = {
      'EAX'   => 'PY' + mod,                         # push eax, pop ecx
      'ECX'   => 'I' + mod,                          # dec ecx
      'EDX'   =>  edxmod + nop + '7RY',			   # dec edx,,, push edx, pop ecx
      'EBX'   => 'SY' + mod,                         # push ebx, pop ecx
      'ESP'   => 'TY' + mod,                         # push esp, pop ecx
      'EBP'   => 'UY' + mod,                         # push ebp, pop ecx
      'ESI'   => 'VY' + mod,                         # push esi, pop ecx
      'EDI'   => 'WY' + mod,                         # push edi, pop ecx
    }

    reg.upcase!
    if (not regprefix.keys.include? reg)
      raise ArgumentError.new("Invalid register name")
    end
    return regprefix[reg]
  end

  def self.gen_decoder(reg, offset)
    decoder =
       gen_decoder_prefix(reg, offset) +
       "jA" +          # push 0x41
       "X" +           # pop eax
       "P" +           # push eax
       "0A0" +         # xor byte [ecx+30], al
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
