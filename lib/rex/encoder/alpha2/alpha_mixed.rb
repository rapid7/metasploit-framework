# -*- coding: binary -*-

require 'rex/encoder/alpha2/generic'

module Rex
module Encoder
module Alpha2

class AlphaMixed < Generic

  # Generates the decoder stub prefix
  #
  # @param [String] reg the register pointing to the encoded payload
  # @param [Fixnum] offset the offset to reach the encoded payload
  # @param [Array] modified_registers accounts the registers modified by the stub
  # @return [String] the alpha mixed decoder stub prefix
  def self.gen_decoder_prefix(reg, offset, modified_registers = [])
    if offset > 32
      raise 'Critical: Offset is greater than 32'
    end

    mod_registers = []
    nop_regs = []
    mod_regs = []
    edx_regs = []

    # use inc ebx as a nop here so we still pad correctly
    if offset <= 16
      nop = 'C' * offset
      nop_regs.push(Rex::Arch::X86::EBX) unless nop.empty?

      mod = 'I' * (16 - offset) + nop + '7QZ'    # dec ecx,,, push ecx, pop edx
      mod_regs.push(Rex::Arch::X86::ECX) unless offset == 16
      mod_regs.concat(nop_regs)
      mod_regs.push(Rex::Arch::X86::EDX)

      edxmod = 'J' * (17 - offset)
      edx_regs.push(Rex::Arch::X86::EDX) unless edxmod.empty?
    else
      mod = 'A' * (offset - 16)
      mod_regs.push(Rex::Arch::X86::ECX) unless mod.empty?

      nop = 'C' * (16 - mod.length)
      nop_regs.push(Rex::Arch::X86::EBX) unless nop.empty?

      mod << nop + '7QZ'
      mod_regs.concat(nop_regs)
      mod_regs.push(Rex::Arch::X86::EDX)

      edxmod = 'B' * (17 - (offset - 16))
      edx_regs.push(Rex::Arch::X86::EDX) unless edxmod.empty?
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

    unless regprefix.keys.include?(reg)
      raise ArgumentError.new('Invalid register name')
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
  # @return [String] the alpha mixed decoder stub
  def self.gen_decoder(reg, offset, modified_registers = [])
    mod_registers = []

    decoder =
       gen_decoder_prefix(reg, offset, mod_registers) +
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

    mod_registers.concat(
      [
        Rex::Arch::X86::ESP,
        Rex::Arch::X86::EAX,
        Rex::Arch::X86::ECX,
        Rex::Arch::X86::EDX
      ])

    mod_registers.uniq!
    modified_registers.concat(mod_registers)

    decoder
  end

end end end end
