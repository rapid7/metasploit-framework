# -*- coding: binary -*-

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class AlphaUpper < Generic
  def self.default_accepted_chars ; ('B' .. 'Z').to_a + ('0' .. '9').to_a ; end

  # Generates the decoder stub prefix
  #
  # @param [String] reg the register pointing to the encoded payload
  # @param [Fixnum] offset the offset to reach the encoded payload
  # @param [Array] modified_registers accounts the registers modified by the stub
  # @return [String] the alpha upper decoder stub prefix
  def self.gen_decoder_prefix(reg, offset, modified_registers = [])
    if offset > 20
      raise 'Critical: Offset is greater than 20'
    end

    mod_registers = []
    nop_regs = []
    mod_regs = []
    edx_regs = []

    # use inc ebx as a nop here so we still pad correctly
    if (offset <= 10)
      nop = 'C' * offset
      nop_regs.push(Rex::Arch::X86::EBX) unless nop.empty?

      mod = 'I' * (10 - offset) + nop + 'QZ'    # dec ecx,,, push ecx, pop edx
      mod_regs.push(Rex::Arch::X86::ECX) unless offset == 10
      mod_regs.concat(nop_regs)
      mod_regs.push(Rex::Arch::X86::EDX)

      edxmod = 'J' * (11 - offset)
      edx_regs.push(Rex::Arch::X86::EDX) unless edxmod.empty?
    else
      mod = 'A' * (offset - 10)
      mod_regs.push(Rex::Arch::X86::ECX) unless mod.empty?

      nop = 'C' * (10 - mod.length)
      nop_regs.push(Rex::Arch::X86::EBX) unless nop.empty?

      mod << nop + 'QZ'
      mod_regs.concat(nop_regs)
      mod_regs.push(Rex::Arch::X86::EDX)

      edxmod = 'B' * (11 - (offset - 10))
      edx_regs.push(Rex::Arch::X86::EDX) unless edxmod.empty?
    end
    regprefix = {
      'EAX'   => 'PY' + mod,                        # push eax, pop ecx
      'ECX'   => 'I' + mod,                         # dec ecx
      'EDX'   =>  edxmod + nop + 'RY',  			  # mod edx,,, push edx, pop ecx
      'EBX'   => 'SY' + mod,                        # push ebx, pop ecx
      'ESP'   => 'TY' + mod,                        # push esp, pop ecx
      'EBP'   => 'UY' + mod,                        # push ebp, pop ecx
      'ESI'   => 'VY' + mod,                        # push esi, pop ecx
      'EDI'   => 'WY' + mod,                        # push edi, pop ecx
    }

    reg.upcase!
    unless regprefix.keys.include?(reg)
      raise ArgumentError.new("Invalid register name")
    end

    case reg
    when 'EDX'
      mod_registers.concat(edx_regs)
      mod_registers.concat(nop_regs)
      mod_registers.push(Rex::Arch::X86::ECX)
    else
      mod_registers.push(Rex::Arch::X86::ECX)
      mod_registers.concat(mod_regs)
    end

    mod_registers.uniq!
    modified_registers.concat(mod_registers)

    return regprefix[reg]
  end

  # Generates the decoder stub
  #
  # @param [String] reg the register pointing to the encoded payload
  # @param [Fixnum] offset the offset to reach the encoded payload
  # @param [Array] modified_registers accounts the registers modified by the stub
  # @return [String] the alpha upper decoder stub
  def self.gen_decoder(reg, offset, modified_registers = [])
    mod_registers = []

    decoder =
      gen_decoder_prefix(reg, offset, mod_registers) +
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

    mod_registers.concat(
      [
        Rex::Arch::X86::ESP,
        Rex::Arch::X86::EAX,
        Rex::Arch::X86::ESI,
        Rex::Arch::X86::ECX,
        Rex::Arch::X86::EDX
      ])

    mod_registers.uniq!
    modified_registers.concat(mod_registers)

    return decoder
  end

end end end end
