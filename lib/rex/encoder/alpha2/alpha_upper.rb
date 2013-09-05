#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class AlphaUpper < Generic
  def self.default_accepted_chars ; ('B' .. 'Z').to_a + ('0' .. '9').to_a ; end

  def self.gen_decoder_prefix(reg, offset)
    if (offset > 20)
      raise "Critical: Offset is greater than 20"
    end

    # use inc ebx as a nop here so we still pad correctly
    if (offset <= 10)
      nop = 'C' * offset
      mod = 'I' * (10 - offset) + nop + 'QZ'    # dec ecx,,, push ecx, pop edx
      edxmod = 'J' * (11 - offset)
    else
      mod = 'A' * (offset - 10)
      nop = 'C' * (10 - mod.length)
      mod << nop + 'QZ'
      edxmod = 'B' * (11 - (offset - 10))
    end
    regprefix = {
      'EAX'   => 'PY' + mod,                        # push eax, pop ecx
      'ECX'   => 'I' + mod,                         # dec ecx
      'EDX'   =>  edxmod + nop + 'RY',  			  # mod edx,,, push edx, pop ecx
      'EBX'   => 'SY' + mod,                        # push ebx, pop ecx
      'ESP'   => 'TY' + mod,                        # push esp, pop ecx
      'EBP'   => 'UY' + mod,                        # push ebp, pop ecx
      'ESI'   => 'VY' + mod,                        # push esi, pop ecx
      'EDI'   => 'WY' + mod,                        # push edi, pop edi
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
