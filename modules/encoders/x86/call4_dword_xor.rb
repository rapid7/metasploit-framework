##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Encoder::Xor

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

end
