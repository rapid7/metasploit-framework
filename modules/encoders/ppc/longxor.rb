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
        This encoder is ghandi's PPC dword xor encoder with some size tweaks
        by HDM.
      },
      'Author'           => [ 'ddz', 'hdm' ],
      'Arch'             => ARCH_PPC,
      'License'          => MSF_LICENSE,
      'Decoder'          =>
        {
          'KeySize'    => 4,
          'BlockSize'  => 4,
          'KeyPack'    => 'N',
        })
  end

  #
  # Returns the decoder stub that is adjusted for the size of
  # the buffer being encoded
  #
  def decoder_stub(state)
    [
      0x7ca52a79,     # 0x1da8 <main>:          xor.    r5,r5,r5
      0x4082fffd,     # 0x1dac <main+4>:        bnel+   0x1da8 <main>
      0x7fe802a6,     # 0x1db0 <main+8>:        mflr    r31
      0x3bff07fa,     # 0x1db4 <main+12>:       addi    r31,r31,2042
      0x38a5f84a,     # 0x1db8 <main+16>:       addi    r5,r5,-1974
      0x3cc09999,     # 0x1dbc <main+20>:       lis     r6, hi16(key)
      0x60c69999,     # 0x1dc0 <main+24>:       ori     r6,r6, lo16(key)
      0x388507ba,     # 0x1dc4 <main+28>:       addi    r4,r5,1978
      0x7c8903a6,     # 0x1dc8 <main+32>:       mtctr   r4
      0x809ff84a,     # 0x1dcc <main+36>:       lwz     r4,-1974(r31)
      0x7c843278,     # 0x1dd0 <main+40>:       xor     r4,r4,r6
      0x909ff84a,     # 0x1dd4 <main+44>:       stw     r4,-1974(r31)
      0x7c05f8ac,     # 0x1dd8 <main+48>:       dcbf    r5,r31
      0x7cff04ac,     # 0x1ddc <main+52>:       sync
      0x7c05ffac,     # 0x1de0 <main+56>:       icbi    r5,r31
      0x3bc507ba,     # 0x1de4 <main+60>:       addi    r30,r5,1978
      0x7ffff215,     # 0x1de8 <main+64>:       add.    r31,r31,r30
      0x4220ffe0,     # 0x1dec <main+68>:       bdnz-   0x1dcc <main+36>
      0x4cff012c,     # 0x1df0 <main+72>:       isync
    ].pack("N*")
  end

  #
  # Fix up the decoder stub now
  #
  def encode_finalize_stub(state, stub)
    icount = state.buf.length / 4

    stub[30, 2] = [ 1974 + icount  ].pack('n')
    stub[22, 2] = [ state.key.to_i ].pack('N')[0, 2]
    stub[26, 2] = [ state.key.to_i ].pack('N')[2, 2]

    stub
  end

end
