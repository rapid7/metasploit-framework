##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = LowRanking

  def initialize
    super(
      'Name' => 'AArch64 XOR Encoder',
      'Description' => %q{
        Encodes all characters in a shell code into alphanumeric code. Algorithm inspired by the paper "Shell codes from A to Z"
      },
      'Author' => 'A5t4t1ne',
      'Arch' => ARCH_AARCH64,
      'License' => MSF_LICENSE
    )
  end

  def encode_block(state, buf)
    # encode the payload

    # puts(buf) 
    # puts(buf.length)

    p = buf
    b = 0x60 # Synchronize with pool
    s = ' ' * 1024 # TODO: needs to be adjusted based on the payload size

    for i in 0...p.length do
      q = p[i].ord
      s[2 * i] = mkchr((q >> 4) & 0xF)
      s[2 * i + 1] = mkchr(q & 0xF)
    end

    s.gsub("@", "P")

    puts(decode_stub(state, buf) + s)
    return decode_stub(state, buf) + s
  end

  def decode_stub(_state, buf)
    # Generate the decoder stub
    return  ''     + # TODO: adr x10, l1 + 0b010011000110100101101
            'JaBq' + # subs	w10, w10, #0x98, lsl #12
            'Je4q' + # subs	w10, w10, #0xd19
            ''     + # TODO: adr x11, l2+0b010011000110001001001
            'kaBq' + # subs	w11, w11, #0x98, lsl #12
            'kM91' + # adds	w11, w11, #0xe53
            'k121' + # adds	w11, w11, #0xc8c
            'sBSj' + # ands	w19, w19, w19, lsr #16
            'sBSj' + # ands	w19, w19, w19, lsr #16
            'b2Sj' + # ands	w2, w19, w19, lsr #12
            ''     + # TODO: loop: tbnz W2, #0b01011, 0b0010011100001100 - not found?
            'R1A9' + # ldrb	w18, [x10, #76]
            'Y5A9' + # ldrb	w25, [x10, #77]
            'Jm01' + # adds	w10, w10, #0xc1b
            'Je0q' + # subs	w10, w10, #0xc19
            'rR2J' + # eon	w18, w19, w18, lsl #20
            ''     + # TODO: .word 0 x72304C00 +33* 25 - ??
            '9CrJ' + # eon	w25, w25, w18, lsr #16
            'yI38' + # strb	w25, [x11, w19, uxtw]
            'ki01' + # adds	w11, w11, #0xc1a
            'ke0q' + # subs	w11, w11, #0xc19
            'Bh01' + # adds	w2, w2, #0xc1a
            'Bd0q' + # subs	w2, w2, #0xc19
            ''     + # TODO: tbz w19, #9, <to lbl 'next'>
            ''     + # TODO: payload
            ''     + # TODO: filler
            ''     + # TODO: tbx w19, #9, <to lbl 'loop'>
            'yikes' 
  end

  def mkchr(ch)
    c = 0x40 + ch # c will always be between 0x41 ('A') and 0x50 ('P')
    return(c.chr)
  end

end
