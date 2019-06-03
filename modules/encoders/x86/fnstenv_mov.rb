##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  def initialize
    super(
      'Name'             => 'Variable-length Fnstenv/mov Dword XOR Encoder',
      'Description'      => %q{
        This encoder uses a variable-length mov equivalent instruction
        with fnstenv for getip.
      },
      'Author'           => 'spoonm',
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'KeySize'   => 4,
          'BlockSize' => 4,
        })
  end

  #
  # Returns the decoder stub that is adjusted for the size of the buffer
  # being encoded.
  #
  def decoder_stub(state)

    # Sanity check that saved_registers doesn't overlap with modified_registers
    if (modified_registers & saved_registers).length > 0
      raise BadGenerateError
    end

    decoder =
      Rex::Arch::X86.set(
        Rex::Arch::X86::ECX,
        (((state.buf.length - 1) / 4) + 1),
        state.badchars) +
      "\xd9\xee" +              # fldz
      "\xd9\x74\x24\xf4" +      # fnstenv [esp - 12]
      "\x5b" +                  # pop ebx
      "\x81\x73\x13XORK" +      # xor_xor: xor DWORD [ebx + 22], xorkey
      "\x83\xeb\xfc" +          # sub ebx,-4
      "\xe2\xf4"                # loop xor_xor

    state.decoder_key_offset = decoder.index('XORK')

    return decoder
  end

  # Indicate that this module can preserve some registers
  def can_preserve_registers?
    true
  end

  # A list of registers always touched by this encoder
  def modified_registers
    [ Rex::Arch::X86::EBX, Rex::Arch::X86::ECX ]
  end

  # Convert the SaveRegisters to an array of x86 register constants
  def saved_registers
    Rex::Arch::X86.register_names_to_ids(datastore['SaveRegisters'])
  end
end
