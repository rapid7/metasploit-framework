##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Encoder::Xor

  def initialize(info={})
    super(
        update_info(
            info,
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
                }
        )
    )
  end

  #
  # Returns the decoder stub that is adjusted for the size of the buffer
  # being encoded.
  #
  def decoder_stub(state)
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

end
