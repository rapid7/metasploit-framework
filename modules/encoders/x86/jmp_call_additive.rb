##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Encoder::XorAdditiveFeedback

  # Uncomment when we get the poly stuff working again.
  #Rank = GreatRanking

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'             => 'Jump/Call XOR Additive Feedback Encoder',
            'Description'      => 'Jump/Call XOR Additive Feedback',
            'Author'           => 'skape',
            'Arch'             => ARCH_X86,
            'License'          => MSF_LICENSE,
            'Decoder'          =>
                {
                    'Stub'       =>
                        "\xfc"                + # cld
                            "\xbbXORK"            + # mov ebx, key
                            "\xeb\x0c"            + # jmp short 0x14
                            "\x5e"                + # pop esi
                            "\x56"                + # push esi
                            "\x31\x1e"            + # xor [esi], ebx
                            "\xad"                + # lodsd
                            "\x01\xc3"            + # add ebx, eax
                            "\x85\xc0"            + # test eax, eax
                            "\x75\xf7"            + # jnz 0xa
                            "\xc3"                + # ret
                            "\xe8\xef\xff\xff\xff", # call 0x8
                    'KeyOffset' => 2,
                    'KeySize'   => 4,
                    'BlockSize' => 4,
                }
        )
    )
  end

  #
  # Append the termination block.
  #
  def encode_end(state)
    state.encoded += [ state.key ].pack(state.decoder_key_pack)
  end

end
