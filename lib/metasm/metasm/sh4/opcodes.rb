#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/sh4/main'

module Metasm
class Sh4
  def addop(name, bin, *args)
    o = Opcode.new name, bin

    o.args.concat(args & @fields_mask.keys)
    (args & @valid_props).each { |p| o.props[p] = true }

    (args & @fields_mask.keys).each { |f|
      o.fields[f] = [@fields_mask[f], @fields_shift[f]]
    }

    @opcode_list << o
  end

  def init
    @opcode_list = []

    # :@rm_ is used for @Rm+
    # :@_rn is used for @-Rn
    # :@r0rm is used for @(R0, Rm) (same for r0rn)
    # :@r0gbr is used for @(R0, GBR)
    @fields_mask = {
      :rm => 0xf, :rn => 0xf,
      :@rm => 0xf, :@rn => 0xf,
      :@rm_ => 0xf, :@rn_ => 0xf,
      :@_rn => 0xf,

      :frm => 0xf, :frn => 0xf,
      :xdm => 0x7, :xdn => 0x7,
      :drm => 0x7, :drn => 0x7,
      :fvm => 0x3, :fvn => 0x3,

      :@r0rm => 0xf, :@r0rn => 0xf,
      :rm_bank => 0x7, :rn_bank => 0x7,

      :@disprm => 0xff, :@dispr0rn => 0xff, :@disprmrn => 0xf0f,
      :@dispgbr => 0xff, :@disppc => 0xff,
      :disp8 => 0xff, :disp12 => 0xfff, :disppc => 0xff,

      :i8 => 0xff, # zero-extendded 8-bit immediate
      :s8 => 0xff, # 8-bit displacement s is sign-extended, doubled and added to PC+4
    }

    @fields_shift = {
      :rm => 4, :rn => 8,
      :@rm => 4, :@rn => 8,
      :@rm_ => 4, :@rn_ => 8,
      :@_rn => 8,

      :frm => 4, :frn => 8,
      :xdm => 5, :xdn => 9,
      :drm => 5, :drn => 9,
      :fvm => 8, :fvn => 10,

      :@r0rm => 4, :@r0rn => 8,
      :rm_bank => 7, :rn_bank => 4,

      :@disprm => 0, :@dispr0rn => 0, :@disprmrn => 0,
      :@dispgbr => 0, :@disppc => 0,
      :disp8 => 0, :disp12 => 0, :disppc => 0,

      :i8 => 0,
      :s8 => 0,
    }

    # implicit operands
    [:vbr, :gbr, :sr, :ssr, :spc, :sgr, :dbr, :mach, :macl, :pr, :fpul, :fpscr, :dbr, :pc, :r0].each { |a| @fields_mask[a] = @fields_shift[a] = 0 }

    @valid_props = [:setip, :saveip, :stopexec , :delay_slot]

    addop 'add', 0b0011 << 12 | 0b1100, :rm, :rn
    addop 'add', 0b0111 << 12, :s8, :rn
    addop 'addc', 0b0011 << 12 | 0b1110, :rm, :rn
    addop 'addv', 0b0011 << 12 | 0b1111, :rm, :rn

    addop 'and', 0b0010 << 12 | 0b1001, :rm, :rn
    addop 'and', 0b11001001 << 8, :i8, :r0
    addop 'and.b', 0b11001101 << 8, :i8, :@r0gbr

    addop 'bf', 0b10001011 << 8, :disp8, :setip
    addop 'bf/s', 0b10001111 << 8, :disp8, :setip, :delay_slot
    addop 'bra', 0b1010 << 12, :disp12, :setip, :stopexec, :delay_slot
    addop 'braf', 0b0000 << 12 | 0b00100011, :rn, :setip, :stopexec, :delay_slot
    addop 'brk', 0b0000000000111011, :stopexec  # causes a pre-execution BREAK exception
    addop 'bsr', 0b1011 << 12, :disp12, :setip, :saveip, :stopexec, :delay_slot
    addop 'bsrf', 0b0000 << 12 | 0b00000011, :rn, :setip, :saveip, :stopexec, :delay_slot
    addop 'bt', 0b10001001 << 8, :disp8, :setip
    addop 'bt/s', 0b10001101 << 8, :disp8, :setip, :delay_slot

    addop 'clrmac', 0b0000000000101000
    addop 'clrs', 0b0000000001001000
    addop 'clrt', 0b0000000000001000

    addop 'cmp/eq', 0b0011 << 12 | 0b0000, :rm, :rn
    addop 'cmp/eq', 0b10001000 << 8, :s8, :r0
    addop 'cmp/ge', 0b0011 << 12 | 0b0011, :rm, :rn
    addop 'cmp/gt', 0b0011 << 12 | 0b0111, :rm, :rn
    addop 'cmp/hi', 0b0011 << 12 | 0b0110, :rm, :rn
    addop 'cmp/hs', 0b0011 << 12 | 0b0010, :rm, :rn
    addop 'cmp/pl', 0b0100 << 12 | 0b00010101, :rn
    addop 'cmp/pz', 0b0100 << 12 | 0b00010001, :rn
    addop 'cmp/str', 0b0010 << 12 | 0b1100, :rm, :rn

    addop 'div0s', 0b0010 << 12 | 0b0111, :rm, :rn
    addop 'div0u', 0b0000000000011001
    addop 'div1', 0b0011 << 12 | 0b0100, :rm, :rn

    addop 'dmuls.l', 0b0011 << 12 | 0b1101, :rm, :rn
    addop 'dmulu.l', 0b0011 << 12 | 0b0101, :rm, :rn

    addop 'dt', 0b0100 << 12 | 0b00010000, :rn

    addop 'exts.b', 0b0110 << 12 | 0b1110, :rm, :rn
    addop 'exts.w', 0b0110 << 12 | 0b1111, :rm, :rn
    addop 'extu.b', 0b0110 << 12 | 0b1100, :rm, :rn
    addop 'extu.w', 0b0110 << 12 | 0b1101, :rm, :rn

    # fpu instructions
    addop 'fabs', 0b1111 << 12 | 0b001011101, :drn
    addop 'fabs', 0b1111 << 12 |  0b01011101, :frn

    addop 'fadd', 0b1111 << 12 | 0b0 << 8 | 0b00000, :drm, :drn
    addop 'fadd', 0b1111 << 12 | 0b0000, :frm, :frn

    addop 'fcmp/eq', 0b1111 << 12 | 0b0 << 8 | 0b00100, :drm, :drn
    addop 'fcmp/eq', 0b1111 << 12 | 0b0100, :frm, :frn

    addop 'fcmp/gt', 0b1111 << 12 | 0b0 << 8 | 0b00101, :drm, :drn
    addop 'fcmp/gt', 0b1111 << 12 | 0b0101, :frm, :frn

    addop 'fcnvds', 0b1111 << 12 | 0b010111101, :drn, :fpul
    addop 'fcnvsd', 0b1111 << 12 | 0b010101101, :fpul, :drn

    addop 'fdiv', 0b1111 << 12 | 0b0 << 8 | 0b00011, :drm, :drn
    addop 'fdiv', 0b1111 << 12 | 0b0011, :frm, :frn
    addop 'fipr', 0b1111 << 12 | 0b11101101, :fvm, :fvn

    addop 'flds', 0b1111 << 12 | 0b00011101, :frn, :fpul
    addop 'fldi0', 0b1111 << 12 | 0b10001101, :frn
    addop 'fldi1', 0b1111 << 12 | 0b10011101, :frn

    addop 'float', 0b1111 << 12 | 0b000101101, :fpul, :drn
    addop 'float', 0b1111 << 12 | 0b00101101, :fpul, :frn

    addop 'fmac', 0b1111 << 12 | 0b1110, :fr0, :frm, :frn

    addop 'fmov', 0b1111 << 12 | 0b0 << 8 | 0b01100, :drm, :drn
    addop 'fmov', 0b1111 << 12 | 0b1 << 8 | 0b01100, :drm, :xdn
    addop 'fmov', 0b1111 << 12 | 0b01010, :drm, :@rn
    addop 'fmov', 0b1111 << 12 | 0b01011, :drm, :@_rn
    addop 'fmov', 0b1111 << 12 | 0b00111, :drm, :@r0rn

    addop 'fmov.s', 0b1111 << 12 | 0b1100, :frm, :frn
    addop 'fmov.s', 0b1111 << 12 | 0b1010, :frm, :@rn
    addop 'fmov.s', 0b1111 << 12 | 0b1011, :frm, :@_rn
    addop 'fmov.s', 0b1111 << 12 | 0b0111, :frm, :@r0rn

    addop 'fmov', 0b1111 << 12 | 0b0 << 8 | 0b11100, :xdm, :drn
    addop 'fmov', 0b1111 << 12 | 0b1 << 8 | 0b11100, :xdm, :xdn
    addop 'fmov', 0b1111 << 12 | 0b11010, :xdm, :@rn
    addop 'fmov', 0b1111 << 12 | 0b11011, :xdm, :@_rn
    addop 'fmov', 0b1111 << 12 | 0b10111, :xdm, :@r0rn

    addop 'fmov', 0b1111 << 12 | 0b0 << 8 | 0b1000, :@rm, :drn
    addop 'fmov', 0b1111 << 12 | 0b0 << 8 | 0b1001, :@rm_, :drn
    addop 'fmov', 0b1111 << 12 | 0b0 << 8 | 0b0110, :@r0rm, :drn

    addop 'fmov.s', 0b1111 << 12 | 0b1000, :@rm, :frn
    addop 'fmov.s', 0b1111 << 12 | 0b1001, :@rm_, :frn
    addop 'fmov.s', 0b1111 << 12 | 0b0110, :@r0rm, :frn

    addop 'fmov', 0b1111 << 12 | 0b1 << 8 | 0b1000, :@rm, :xdn
    addop 'fmov', 0b1111 << 12 | 0b1 << 8 | 0b1001, :@rm_, :xdn
    addop 'fmov', 0b1111 << 12 | 0b1 << 8 | 0b0110, :@r0rm, :xdn

    addop 'fmul', 0b1111 << 12 | 0b0 << 8 | 0b00010, :drm, :drn
    addop 'fmul', 0b1111 << 12 | 0b0010, :frm, :frn

    addop 'fneg', 0b1111 << 12 | 0b001001101, :drn
    addop 'fneg', 0b1111 << 12 | 0b01001101, :frn

    addop 'frchg', 0b1111101111111101
    addop 'fschg', 0b1111001111111101

    addop 'fsqrt', 0b1111 << 12 | 0b001101101, :drn
    addop 'fsqrt', 0b1111 << 12 | 0b01101101, :frn
    addop 'fsts', 0b1111 << 12 | 0b00001101, :fpul, :frn

    addop 'fsub', 0b1111 << 12 | 0b0 << 8 | 0b00001, :@drm, :drn
    addop 'fsub', 0b1111 << 12 | 0b0001, :frm, :frn

    addop 'ftrc', 0b1111 << 12 | 0b000111101, :drn, :fpul
    addop 'ftrc', 0b1111 << 12 | 0b00111101, :frn, :fpul
    addop 'ftrv', 0b1111 << 12 | 0b0111111101, :xmtrx, :fvn

    addop 'jmp', 0b0100 << 12 | 0b00101011, :rn, :setip, :stopexec, :delay_slot
    addop 'jsr', 0b0100 << 12 | 0b00001011, :rn, :setip, :saveip, :stopexec, :delay_slot

    addop 'ldc', 0b0100 << 12 | 0b00011110, :rn, :gbr
    addop 'ldc', 0b0100 << 12 | 0b00001110, :rn, :sr  # privileged instruction
    addop 'ldc', 0b0100 << 12 | 0b00101110, :rn, :vbr # privileged instruction
    addop 'ldc', 0b0100 << 12 | 0b00111110, :rn, :ssr # privileged instruction
    addop 'ldc', 0b0100 << 12 | 0b01001110, :rn, :spc # privileged instruction
    addop 'ldc', 0b0100 << 12 | 0b11111010, :rn, :dbr # privileged instruction
    addop 'ldc', 0b0100 << 12 | 0b1 << 7 | 0b1110, :rn, :rn_bank # privileged instruction

    addop 'ldc.l', 0b0100 << 12 | 0b00010111, :@rn_, :gbr
    addop 'ldc.l', 0b0100 << 12 | 0b00000111, :@rn_, :sr  # privileged instruction
    addop 'ldc.l', 0b0100 << 12 | 0b00100111, :@rn_, :vbr # privileged instruction
    addop 'ldc.l', 0b0100 << 12 | 0b00110111, :@rn_, :ssr # privileged instruction
    addop 'ldc.l', 0b0100 << 12 | 0b01000111, :@rn_, :spc # privileged instruction
    addop 'ldc.l', 0b0100 << 12 | 0b11110110, :@rn_, :dbr # privileged instruction
    addop 'ldc.l', 0b0100 << 12 | 0b1 << 7 | 0b0111, :@rn_, :rn_bank # privileged instruction

    addop 'lds', 0b0100 << 12 | 0b01101010, :rn, :fpscr
    addop 'lds.l', 0b0100 << 12 | 0b01100110, :@rn_, :fpscr
    addop 'lds', 0b0100 << 12 | 0b01011010, :rn, :fpul
    addop 'lds.l', 0b0100 << 12 | 0b01010110, :@rn_, :fpul
    addop 'lds', 0b0100 << 12 | 0b00001010, :rn, :mach
    addop 'lds.l', 0b0100 << 12 | 0b00000110, :@rn_, :mach
    addop 'lds', 0b0100 << 12 | 0b00011010, :rn, :macl
    addop 'lds.l', 0b0100 << 12 | 0b00010110, :@rn_, :macl
    addop 'lds', 0b0100 << 12 | 0b00101010, :rn, :pr
    addop 'lds.l', 0b0100 << 12 | 0b00100110, :@rn_, :pr

    addop 'ldtlb', 0b0000000000111000

    addop 'mac.l', 0b0000 << 12 | 0b1111, :@rm_, :@rn_
    addop 'mac.w', 0b0100 << 12 | 0b1111, :@rm_, :@rn_

    addop 'mov', 0b0110 << 12 | 0b0011, :rm, :rn
    addop 'mov', 0b1110 << 12, :s8, :rn

    addop 'mov.b', 0b0010 << 12 | 0b0000, :rm, :@rn
    addop 'mov.b', 0b0010 << 12 | 0b0100, :rm, :@_rn
    addop 'mov.b', 0b0000 << 12 | 0b0100, :rm, :@r0rn
    addop 'mov.b', 0b11000000 << 8, :r0, :@dispgbr
    addop 'mov.b', 0b10000000 << 8, :r0, :@dispr0rn
    addop 'mov.b', 0b0110 << 12 | 0b0000, :@rm, :rn
    addop 'mov.b', 0b0110 << 12 | 0b0100, :@rm_, :rn
    addop 'mov.b', 0b0000 << 12 | 0b1100, :@r0rm, :rn
    addop 'mov.b', 0b11000100 << 8, :@dispgbr, :r0
    addop 'mov.b', 0b10000100 << 8, :@dispr0rn, :r0

    addop 'mov.l', 0b0010 << 12 | 0b0010, :rm, :@rn
    addop 'mov.l', 0b0010 << 12 | 0b0110, :rm, :@_rn
    addop 'mov.l', 0b0000 << 12 | 0b0110, :rm, :@r0rn
    addop 'mov.l', 0b11000010 << 8, :r0, :@dispgbr
    addop 'mov.l', 0b0001 << 12, :rm, :@disprmrn
    addop 'mov.l', 0b0110 << 12 | 0b0010, :@rm, :rn
    addop 'mov.l', 0b0110 << 12 | 0b0110, :@rm_, :rn
    addop 'mov.l', 0b0000 << 12 | 0b1110, :@r0rm, :rn
    addop 'mov.l', 0b11000110 << 8, :@dispgbr, :r0
    addop 'mov.l', 0b1101 << 12, :@disppc, :rn
    addop 'mov.l', 0b0101 << 12, :@disprm, :rn

    addop 'mov.w', 0b0010 << 12 | 0b0001, :rm, :@rn
    addop 'mov.w', 0b0010 << 12 | 0b0101, :rm, :@_rn
    addop 'mov.w', 0b0000 << 12 | 0b0101, :rm, :@r0rn
    addop 'mov.w', 0b11000001 << 8, :r0, :@dispgbr
    addop 'mov.w', 0b10000001 << 8, :r0, :@dispr0rn
    addop 'mov.w', 0b0110 << 12 | 0b0001, :@rm, :rn
    addop 'mov.w', 0b0110 << 12 | 0b0101, :@rm_, :rn
    addop 'mov.w', 0b0000 << 12 | 0b1101, :@r0rm, :rn
    addop 'mov.w', 0b11000101 << 8, :@dispgbr, :r0
    addop 'mov.w', 0b1001 << 12, :@disppc, :rn
    addop 'mov.w', 0b10000101 << 8, :@disprm, :r0

    addop 'mova', 0b11000111 << 8, :disppc, :r0 # calculates an effective address using PC-relative with displacement addressing
    addop 'movca.l', 0b0000 << 12 | 11000011, :r0, :@rn # stores the long-word in R0 to memory at the effective address specified in Rn.     

    addop 'movt', 0b0000 << 12 | 0b00101001, :rn # copies the T-bit to Rn

    addop 'mul.l', 0b0000 << 12 | 0b0111, :rm, :rn
    addop 'muls.w', 0b0010 << 12 | 0b1111, :rm, :rn
    addop 'mulu.w', 0b0010 << 12 | 0b1110, :rm, :rn

    addop 'neg', 0b0110 << 12 | 0b1011, :rm, :rn
    addop 'negc', 0b0110 << 12 | 0b1010, :rm, :rn

    addop 'nop', 0b0000000000001001

    addop 'not', 0b0110 << 12 | 0b0111, :rm, :rn

    addop 'ocbi', 0b0000 << 12 | 0b10010011, :@rn # invalidates an operand cache block
    addop 'ocbp', 0b0000 << 12 | 0b10100011, :@rn # purges an operand cache block
    addop 'ocbwb', 0b0000 << 12 | 0b10110011, :@rn # write-backs an operand cache block

    addop 'or', 0b0010 << 12 | 0b1011, :rm, :rn
    addop 'or', 0b11001011 << 8, :i8, :r0
    addop 'or.b', 0b11001111 << 8, :i8, :@r0gbr

    addop 'pref', 0b0000 | 0b10000011, :@rn # indicates a software-directed data prefetch

    addop 'rotcl', 0b0100 | 0b00100100, :rn
    addop 'rotcr', 0b0100 | 0b00100101, :rn
    addop 'rotl',  0b0100 | 0b00000100, :rn
    addop 'rotr',  0b0100 | 0b00000101, :rn

    addop 'rte', 0b0000000000101011, :setip, :stopexec, :delay_slot # returns from an exception or interrupt handling routine,  privileged instruction
    addop 'rts', 0b0000000000001011, :setip, :stopexec, :delay_slot # returns from a subroutine

    addop 'sets', 0b0000000001011000
    addop 'sett', 0b0000000000011000

    addop 'shad',   0b0100 << 12 | 0b1100, :rm, :rn
    addop 'shal',   0b0100 << 12 | 0b00100000, :rn
    addop 'shar',   0b0100 << 12 | 0b00100001, :rn
    addop 'shld',   0b0100 << 12 | 0b1101, :rm, :rn
    addop 'shll',   0b0100 << 12 | 0b00000000, :rn
    addop 'shll2',  0b0100 << 12 | 0b00001000, :rn
    addop 'shll8',  0b0100 << 12 | 0b00011000, :rn
    addop 'shll16', 0b0100 << 12 | 0b00101000, :rn
    addop 'shlr',   0b0100 << 12 | 0b00000001, :rn
    addop 'shlr2',  0b0100 << 12 | 0b00001001, :rn
    addop 'shlr8',  0b0100 << 12 | 0b00011001, :rn
    addop 'shlr16', 0b0100 << 12 | 0b00101001, :rn

    addop 'sleep', 0b0000000000011011 # privileged instruction

    addop 'stc', 0b0000 << 12 | 0b00000010, :sr, :rn
    addop 'stc', 0b0000 << 12 | 0b00100010, :vbr, :rn
    addop 'stc', 0b0000 << 12 | 0b00110010, :ssr, :rn
    addop 'stc', 0b0000 << 12 | 0b01000010, :spc, :rn
    addop 'stc', 0b0000 << 12 | 0b00111010, :sgr, :rn
    addop 'stc', 0b0000 << 12 | 0b11111010, :dbr, :rn
    addop 'stc', 0b0000 << 12 | 0b1 << 7 | 0b0010, :rm_bank, :@_rn
    addop 'stc', 0b0000 << 12 | 0b00010010, :gbr, :rn

    addop 'stc.l', 0b0100 << 12 | 0b00000011, :sr, :@_rn
    addop 'stc.l', 0b0100 << 12 | 0b00100011, :vbr, :@_rn
    addop 'stc.l', 0b0100 << 12 | 0b00110011, :ssr, :@_rn
    addop 'stc.l', 0b0100 << 12 | 0b01000011, :spc, :@_rn
    addop 'stc.l', 0b0100 << 12 | 0b00110010, :sgr, :@_rn
    addop 'stc.l', 0b0100 << 12 | 0b11110010, :dbr, :@_rn
    addop 'stc.l', 0b0100 << 12 | 0b1 << 7 | 0b0011, :rm_bank, :@_rn
    addop 'stc.l', 0b0100 << 12 | 0b00010011, :gbr, :@_rn

    addop 'sts',   0b0000 << 12 | 0b01101010, :fpscr, :rn
    addop 'sts.l', 0b0100 << 12 | 0b01100010, :fpscr, :@_rn
    addop 'sts',   0b0000 << 12 | 0b01011010, :fpul, :rn
    addop 'sts.l', 0b0100 << 12 | 0b01010010, :fpul, :@_rn
    addop 'sts',   0b0000 << 12 | 0b00001010, :mach, :rn
    addop 'sts.l', 0b0100 << 12 | 0b00000010, :mach, :@_rn
    addop 'sts',   0b0000 << 12 | 0b00011010, :macl, :rn
    addop 'sts.l', 0b0100 << 12 | 0b00010010, :macl, :@_rn
    addop 'sts',   0b0000 << 12 | 0b00101010, :pr, :rn
    addop 'sts.l', 0b0100 << 12 | 0b00100010, :pr, :@_rn

    addop 'sub', 0b0011 << 12 | 0b1000, :rm, :rn
    addop 'subc', 0b0011 << 12 | 0b1010, :rm, :rn
    addop 'subv', 0b0011 << 12 | 0b1011, :rm, :rn

    addop 'swap.b', 0b0110 << 12 | 0b1000, :rm, :rn
    addop 'swap.w', 0b0110 << 12 | 0b1001, :rm, :rn

    addop 'tas.b', 0b0100 << 12 | 0b00011011, :@rn
    addop 'trapa', 0b11000011 << 8, :i8, :setip, :stopexec # This instruction causes a pre-execution trap.

    addop 'tst', 0b0010 << 12 | 0b1000, :rm, :rn
    addop 'tst', 0b11001000 << 8, :i8, :r0
    addop 'tst.b', 0b11001100 << 8, :i8, :@r0gbr

    addop 'xor', 0b0010 << 12 | 0b1010, :rm, :rn
    addop 'xor', 0b11001010 << 8, :i8, :r0
    addop 'xob.b', 0b11001110 << 8, :i8, :@r0gbr

    addop 'xtrct', 0b0010 << 12 | 0b1101, :rm, :rn
  end

end

end
