#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/arc/main'

module Metasm
class ARC
  def addop32(name, bin, *args)
    addop(:ac32, name, bin, *args)
  end

  def addop16(name, bin, *args)
    addop(:ac16, name, bin, *args)
  end

  def addop(mode, name, bin, *args)
    o = Opcode.new(name)
    o.bin = bin
    args.each { |a|
      o.args << a if @fields_mask[a]
      o.props[a] = true if @valid_props[a]
      o.fields[a] = [@fields_mask[a], @fields_shift[a]] if @fields_mask[a]
    }
    (mode == :ac16) ? (@opcode_list16 << o) : (@opcode_list32 << o)
  end

  def init_opcode_list
    @opcode_list16 = []
    @opcode_list32 = []

    @valid_props.update :flag_update => true, :delay_slot => true
    @cond_suffix = [''] + %w[z nz p n cs cc vs vc gt ge lt le hi ls pnz]
    #The remaining 16 condition codes (10-1F) are available for extension
    @cond_suffix += (0x10..0x1f).map{ |i| "extcc#{i.to_s(16)}" }

    # Compact 16-bits operands field masks
    fields_mask16 = {
      :ca => 0x7, :cb => 0x7, :cb2 => 0x7, :cb3 => 0x7, :cc => 0x7,
      :cu => 0x1f,
      :ch => 0b11100111,

      # immediate (un)signed
      :cu3 => 0x7, :cu8 => 0xff,
      # cu7 is 32-bit aligned, cu6 is 16-bit aligned, cu6 is 8-bit aligned
      :cu5 => 0x1f, :cu5ee => 0x1f, :cu6 => 0x3f, :cu7 => 0x7f,

      :cs9 => 0x1ff, :cs9ee => 0x1ff, :cs10 => 0x1ff, :cs11 => 0x1ff,

      # signed displacement
      :cdisps7=> 0x3f, :cdisps8 => 0x7f, :cdisps10 => 0x1ff, :cdisps13 => 0x7FF,

      # memref [b+u], [sp,u], etc.
      :@cb => 0x7, :@cbu7 => 0b11100011111, :@cbu6 => 0b11100011111, :@cbu5 => 0b11100011111,
      :@cspu7 => 0b11111, :@cbcc => 0b111111,
      :@gps9 => 0x1ff, :@gps10 => 0x1ff, :@gps11 => 0x1ff,

      # implicit operands
      :climm => 0x0, :cr0 => 0x0,
      :blink => 0x0, :@blink => 0x0, :gp => 0x0, :sp => 0x0, :sp2 => 0x0, :zero => 0x0
    }

    fields_shift16 = {
      :ca => 0x0, :cb => 0x8, :cb2 => 0x8, :cb3 => 0x8, :cc => 0x5,
      :cu => 0x0,

      # immediate (un)signed
      :ch => 0x0,
      :cu3 => 0x0, :cu5 => 0, :cu5ee => 0, :cu6 => 5, :cu7 => 0x0, :cu8 => 0x0,
      :cs9 => 0x0, :cs9ee => 0x0, :cs10 => 0x0, :cs11 => 0x0,

      # signed displacement
      :cdisps7=> 0x0, :cdisps8 => 0x0, :cdisps10 => 0x0, :cdisps13 => 0x0,

      # memref [b+u]
      :@cb => 0x8, :@cbu7 => 0x0, :@cbu6 => 0x0, :@cbu5 => 0x0,
      :@cspu7 => 0x0, :@cbcc => 0x5,
      :@gps9 => 0x0, :@gps10 => 0x0, :@gps11 => 0x0,

      # implicit operands
      :climm => 0x0, :cr0 => 0x0,
      :blink => 0x0, :@blink => 0x0, :gp => 0x0, :sp => 0x0, :sp2 => 0x0, :zero => 0x0,
    }

    fields_mask32 = {
      :a => 0x3f, :b => 0b111000000000111, :bext => 0b111000000000111,
      :c => 0x3f, :@c => 0x3f, :cext => 0x3f, :@cext => 0x3f,

      :u6 => 0x3f, :u6e => 0x3f,
      :s8e => 0x1fd, :s9 => 0x7f,
      :s12 => 0xfff, :s12e => 0xfff,
      :s21e => 0x1ffBff, :s21ee => 0x1ff3ff,
      :s25e => 0x7feffcf, :s25ee => 0x7fcffcf,

      :@bs9 => 0x7fff, :@bc => 0x1ff, :@bextcext => 0x1C01FF,

      :limm => 0x0, :@limm => 0x0,
      :@limmc => 0x3f, :@blimm => 0x7,

      :auxlimm => 0x0, :auxs12 => 0xfff,

      :ccond => 0x1f, #condition codes
      :delay5 => 1, :delay16 => 1,# delay slot
      :flags15 => 0x1, :flags16 => 0x1,
      :signext6 => 0x1, :signext16 => 0x1,
      :cache5 => 0x1, :cache11 => 0x1, :cache16 => 0x1, # data cache mode field
      :sz1 => 0x3, :sz7 => 0x3, :sz16 => 0x3,  :sz17 => 0x3, #data size field
      :wb3 => 0x3, :wb9 => 0x3, :wb22 => 0x3, #write-back flag
      :zero => 0x0, :b2 => 0x0, :@ilink1 => 0x0, :@ilink2 => 0x0
    }
    #FIXME

    fields_shift32 = {
      :a => 0x0, :b => 0xC, :bext => 0xC,
      :c => 0x6, :@c => 0x6, :cext => 0x6, :@cext => 0x6,

      :u6 => 0x6, :u6e =>0x6,
      :s8e => 15, :s9 => 0x11,
      :s12 => 0x0, :s12e => 0,
      :s21e => 0x6, :s21ee => 0x6,
      :s25e => 0, :s25ee => 0,

      :limm => 0x0, :@limm => 0x0,
      :@limmc => 0x6, :@blimm => 0x18,

      :auxlimm => 0x0, :auxs12 => 0,

      :@bs9 => 12, :@bc => 6, :@bextcext => 6,

      :ccond => 0, #condition codes
      :delay5 => 5, :delay16 => 16,# delay slot
      :flags15 => 15, :flags16 => 16,
      :signext6 => 6, :signext16 => 16,
      :cache5 => 5, :cache11 => 11, :cache16 =>  16, # data cache mode field
      :sz1 => 1, :sz7 => 7, :sz16 => 16, :sz17 => 17, #data size field
      :wb3 => 3, :wb9 => 9, :wb22 => 22, #write-back flag
      :zero => 0x0, :b2 => 0x0, :@ilink1 => 0, :@ilink2 => 0,
    }

    @fields_mask = fields_mask16.merge(fields_mask32)
    @fields_shift = fields_shift16.merge(fields_shift32)

    init_arc_compact16()
    init_arc_compact32()

    {16 => @opcode_list16, 32 => @opcode_list32}
  end

  def add_artihm_op(op, majorcode, subcode, *flags)
    #           0bxxxxxbbb00xxxxxxFBBBCCCCCCAAAAAA
    addop32 op, 0b00000000000000000000000000000000 | majorcode << 0x1b | subcode << 16, :a, :bext, :cext, :flags15
    #           0bxxxxxbbb01xxxxxxFBBBuuuuuuAAAAAA
    addop32 op, 0b00000000010000000000000000000000 | majorcode << 0x1b | subcode << 16, :a, :b, :u6, :flags15
    #           0bxxxxxbbb10xxxxxxFBBBssssssSSSSSS
    addop32 op, 0b00000000100000000000000000000000 | majorcode << 0x1b | subcode << 16, :b, :b2, :s12, :flags15
    #           0bxxxxxbbb11xxxxxxFBBBCCCCCC0QQQQQ
    addop32 op, 0b00000000110000000000000000000000 | majorcode << 0x1b | subcode << 16, :b, :b2, :cext, :ccond, :flags15
    #           0bxxxxxbbb11xxxxxxFBBBuuuuuu1QQQQQ
    addop32 op, 0b00000000110000000000000000100000 | majorcode << 0x1b | subcode << 16, :b, :b2, :u6, :ccond, :flags15
  end

  def add_logical_op(op, majorcode, subcode, *flags)
    #           0b00100bbb00xxxxxxFBBBCCCCCCAAAAAA
    addop32 op, 0b00100000000000000000000000000000 | majorcode << 0x1b | subcode << 16, :a, :bext, :c, :flags15
    #           0b00100bbb01xxxxxxFBBBuuuuuuAAAAAA
    addop32 op, 0b00100000010000000000000000000000 | majorcode << 0x1b | subcode << 16, :a, :b, :u6, :flags15
    #           0b00100bbb11xxxxxxFBBBCCCCCC0QQQQQ
    # WTF
    addop32 op, 0b00100000110000000000000000000000 | majorcode << 0x1b | subcode << 16, :b, :b2, :c, :ccond, :flags15
    #           0b00100bbb11xxxxxxFBBBuuuuuu1QQQQQ
    addop32 op, 0b00100000110000000000000000100000 | majorcode << 0x1b | subcode << 16, :b, :b2, :u6, :ccond, :flags15
  end

  def add_artihm_op_reduce(op, majorcode, subcode)
    #           0bxxxxxbbb00101111FBBBCCCCCCxxxxxx
    addop32 op, 0b00000000001011110000000000000000 | majorcode << 0x1b | subcode, :b, :cext, :flags15
    #           0bxxxxxbbb01101111FBBBuuuuuuxxxxxx
    addop32 op, 0b00000000011011110000000000000000 | majorcode << 0x1b | subcode, :b, :u6, :flags15
  end

  def add_condbranch_op(op, ccond)
    #           0b00001bbbsssssss1SBBBUUUUUUN0xxxx
    addop32 op, 0b00001000000000010000000000000000 | ccond, :bext, :cext, :s8e, :setip, :delay5
    #           0b00001bbbsssssss1SBBBUUUUUUN1xxxx
    addop32 op, 0b00001000000000010000000000010000 | ccond, :b, :u6, :s8e, :setip, :delay5
  end

  def add_condjmp_op()
    #            0b00100RRR1110000D0RRRCCCCCC0QQQQQ
    addop32 'j', 0b00100000111000000000000000000000, :@cext, :ccond, :setip, :delay16
    #            0b00100RRR1110000D0RRRuuuuuu1QQQQQ
    addop32 'j', 0b00100000111000000000000000100000, :u6, :ccond, :setip, :delay16
    #            0b00100RRR111000001RRR0111010QQQQQ
    addop32 'j', 0b00100000111000001000011101000000, :@ilink1, :ccond, :setip, :flag_update
    #            0b00100RRR111000001RRR0111100QQQQQ
    addop32 'j', 0b00100000111000001000011110000000, :@ilink2, :ccond, :setip, :flag_update
  end

  def add_condjmplink_op()
    #             0b00100RRR111000100RRRCCCCCC0QQQQQ
    addop32 'jl', 0b00100000111000100000000000000000, :@cext, :ccond, :setip, :saveip, :delay16
    #             0b00100RRR111000100RRRuuuuuu1QQQQQ
    addop32 'jl', 0b00100000111000100000000000100000, :u6, :ccond, :setip, :saveip, :delay16
  end

  def init_arc_compact32

    add_artihm_op_reduce 'abs',   0b00100, 0b001001
    add_artihm_op_reduce 'abss',  0b00101, 0b000101
    add_artihm_op_reduce 'abssw', 0b00101, 0b000100

    add_artihm_op 'adc',   0b00100, 0b000001
    add_artihm_op 'add',   0b00100, 0b000000
    add_artihm_op 'add1',  0b00100, 0b010100
    add_artihm_op 'add2',  0b00100, 0b010101
    add_artihm_op 'add3',  0b00100, 0b010110
    add_artihm_op 'adds',  0b00101, 0b000110
    add_artihm_op 'addsw', 0b00101, 0b010101, :extended
    add_artihm_op 'addsdw',0b00101, 0b101000, :extended
    add_artihm_op 'and'   ,0b00100, 0b000100

    add_artihm_op_reduce 'asl', 0b00100, 0b000000

    add_artihm_op 'asl',  0b00101, 0b000000, :extended
    add_artihm_op 'asls', 0b00101, 0b001010, :extended

    add_artihm_op_reduce 'asr', 0b00100, 0b000001

    add_artihm_op 'asr',  0b00101, 0b000010
    add_artihm_op 'asrs', 0b00101, 0b001011

    #                0b00001bbbsssssss1SBBBCCCCCCN01110
    addop32 'bbit0', 0b00001000000000010000000000001110, :b, :c, :s9, :delay5, :setip
    #                0b00001bbbsssssss1SBBBuuuuuuN11110
    addop32 'bbit0', 0b00001000000000010000000000011110, :b, :u6, :s9, :delay5, :setip
    #                0b00001bbbsssssss1SBBBCCCCCCN01111
    addop32 'bbit1', 0b00001000000000010000000000001111, :b, :c, :s9, :delay5, :setip
    #                0b00001bbbsssssss1SBBBuuuuuuN11111
    addop32 'bbit1', 0b00001000000000010000000000011111, :b, :u6, :s9, :delay5, :setip

    #            0b00000ssssssssss0SSSSSSSSSSNQQQQQ
    addop32 'b', 0b00000000000000000000000000000000, :s21e, :ccond, :delay5, :setip
    #            0b00000ssssssssss1SSSSSSSSSSNRtttt
    addop32 'b', 0b00000000000000010000000000000000, :s25e, :delay5, :setip, :stopexec
    # WTF: unknown encoding, bit 5 should be reserved
    addop32 'b', 0b00000000000000010000000000010000, :s25e, :delay5, :setip, :stopexec

    add_logical_op 'bclr', 0b00100, 0b010000
    add_artihm_op  'bic',  0b00100, 0b000110

    #             0b00001sssssssss00SSSSSSSSSSNQQQQQ
    addop32 'bl', 0b00001000000000000000000000000000, :s21ee, :ccond, :delay5, :setip, :saveip
    #             0b00001sssssssss10SSSSSSSSSSNRtttt
    addop32 'bl', 0b00001000000000100000000000000000, :s25ee, :delay5, :setip, :saveip, :stopexec

    add_logical_op 'bmsk', 0b00100, 0b010011

    add_condbranch_op 'breq', 0b0000
    add_condbranch_op 'brne', 0b0001
    add_condbranch_op 'brlt', 0b0010
    add_condbranch_op 'brge', 0b0011
    add_condbranch_op 'brlo', 0b0100
    add_condbranch_op 'brhs', 0b0101

    addop32 'brk', 0b00100101011011110000000000111111, :stopexec

    add_logical_op 'bset', 0b00100, 0b001111

    #               0b00100bbb110100011BBBCCCCCC0QQQQQ
    addop32 'btst', 0b00100000110100011000000000000000, :bext, :c, :ccond
    #               0b00100bbb110100011BBBuuuuuu1QQQQQ
    addop32 'btst', 0b00100000110100011000000000100000, :b, :u6, :ccond
    #  WTF          0b00100bbb010100011BBBuuuuuu0QQQQQ
    addop32 'btst', 0b00100000010100011000000000000000, :b, :u6, :ccond

    add_logical_op 'bxor', 0b00100, 0b010010

    #              0b00100bbb100011001BBBssssssSSSSSS
    addop32 'cmp', 0b00100000100011001000000000000000, :b, :s12
    # WTF unknown encoding ...
    #              0b00100bbb010011001BBBssssssSSSSSS
    addop32 'cmp', 0b00100000010011001000000000000000, :b, :s12
    #              0b00100bbb110011001BBBuuuuuu1QQQQQ
    addop32 'cmp', 0b00100000110011001000000000100000, :b, :u6, :ccond
    # WTF unknown encoding ...
    #              0b00100bbb010011001BBBssssssSSSSSS
    addop32 'cmp', 0b00100000000011001000000000000000, :bext, :cext, :ccond
    #              0b00100bbb110011001BBBCCCCCC0QQQQQ
    addop32 'cmp', 0b00100000110011001000000000000000, :bext, :cext, :ccond

    add_artihm_op 'divaw', 0b00101, 0b001000, :extended

    #             0b00100bbb00101111DBBBCCCCCC001100
    addop32 'ex', 0b00100000001011110000000000001100, :b, :@cext, :cache16
    #             0b00100bbb01101111DBBBuuuuuu001100
    addop32 'ex', 0b00100000011011110000000000001100, :b, :@u6, :cache16

    add_artihm_op_reduce 'extb', 0b00100, 0b000111
    add_artihm_op_reduce 'extw', 0b00100, 0b001000

    # WTF unknown encoding ...
    #               0b00100rrr111010010RRRCCCCCC0QQQQQ
    addop32 'flag', 0b00100000001010010000000000000000, :cext, :ccond, :flag_update
    #               0b00100rrr111010010RRRuuuuuu1QQQQQ
    addop32 'flag', 0b00100000001010010000000000100000, :u6, :ccond, :flag_update
    #               0b00100rrr101010010RRRssssssSSSSSS
    addop32 'flag', 0b00100000011010010000000000000000, :s12, :flag_update

    add_condjmp_op()
    add_condjmplink_op()

    #              0b00100RRR001000000RRRCCCCCCRRRRRR
    addop32 'j',   0b00100000001000000000000000000000, :@cext, :delay16, :setip, :stopexec
    #              0b00100RRR011000000RRRuuuuuuRRRRRR
    addop32 'j',   0b00100000011000000000000000000000, :u6, :delay16, :setip, :stopexec
    #              0b00100RRR101000000RRRssssssSSSSSS
    addop32 'j',   0b00100000101000000000000000000000, :s12, :delay16, :setip, :stopexec
    #              0b00100RRR001000001RRR011101RRRRRR
    addop32 'j.f', 0b00100000001000001000011101000000, :@ilink1, :flag_update, :setip, :stopexec
    #              0b00100RRR001000001RRR011110RRRRRR
    addop32 'j.f', 0b00100000001000001000011110000000, :@ilink2, :flag_update, :setip, :stopexec

    #             0b00100RRR0010001D0RRRCCCCCCRRRRRR
    addop32 'jl', 0b00100000001000100000000000000000, :@cext, :delay16, :setip, :saveip, :stopexec
    #             0b00100RRR0110001D0RRRuuuuuuRRRRRR
    addop32 'jl', 0b00100000011000100000000000000000, :u6, :delay16, :setip, :saveip, :stopexec
    #             0b00100RRR1010001D0RRRssssssSSSSSS
    addop32 'jl', 0b00100000101000100000000000000000, :s12, :delay16, :setip, :saveip, :stopexec

    #             0b00010bbbssssssssSBBBDaaZZXAAAAAA
    addop32 'ld', 0b00010000000000000000000000000000, :a, :@bs9, :sz7, :signext6, :wb9, :cache11

    #             0b00100bbbaa110ZZXDBBBCCCCCCAAAAAA
    addop32 'ld', 0b00100000001100000000000000000000, :a, :@bextcext, :sz17, :signext16, :wb22, :cache11

    #             0b00100RRR111010000RRRuuuuuu1QQQQQ
    addop32 'lp', 0b00100000111010000000000000100000, :u6e, :ccond, :setip
    #             0b00100RRR101010000RRRssssssSSSSSS
    addop32 'lp', 0b00100000101010000000000000000000, :s12e, :setip

    #             0b00100bbb001010100BBBCCCCCCRRRRRR
    addop32 'lr', 0b00100000101010100000000000000000, :b, :@c
    #             0b00100bbb001010100BBB111110RRRRRR
    addop32 'lr', 0b00100000001010100000111110000000, :b, :auxlimm
    #             0b00100bbb101010100BBBssssssSSSSSS
    addop32 'lr', 0b00100000011010100000000000000000, :b, :auxs12
    # WTF unknown encoding ...
    #             0b00100bbb101010100BBBssssssSSSSSS
    addop32 'lr', 0b00100000101010100000000000000000, :b, :auxs12

    add_artihm_op_reduce 'lsr', 0b00100, 0b000010

    add_artihm_op 'lsr', 0b00101, 0b000001
    add_artihm_op 'max', 0b00100, 0b001000
    add_artihm_op 'min', 0b00100, 0b001001

    #              0b00100bbb10001010FBBBssssssSSSSSS
    addop32 'mov', 0b00100000100010100000000000000000, :b, :s12, :flags15
    # WTF unknown encoding ...
    #              0b00100bbb01001010FBBBssssssSSSSSS
    addop32 'mov', 0b00100000010010100000000000000000, :b, :s12, :flags15
    #              0b00100bbb11001010FBBBCCCCCC0QQQQQ
    addop32 'mov', 0b00100000110010100000000000000000, :b, :cext, :ccond , :flags15
    # WTF unknown encoding ..
    #              0b00100bbb00001010FBBBCCCCCC0QQQQQ
    addop32 'mov', 0b00100000000010100000000000000000, :b, :cext, :ccond , :flags15
    #              0b00100bbb11001010FBBBuuuuuu1QQQQQ
    addop32 'mov', 0b00100000110010100000000000100000, :b, :u6, :ccond , :flags15

    add_artihm_op 'mpy',   0b00100, 0b011010, :extended
    add_artihm_op 'mpyh',  0b00100, 0b011011, :extended
    add_artihm_op 'mpyhu', 0b00100, 0b011100, :extended
    add_artihm_op 'mpyu',  0b00100, 0b011101, :extended

    # WTF: neg instruction is not differenciated from a rsub :a, :b, :u6
    # :             0b00100bbb01001110FBBB000000AAAAAA
    #addop32 'neg', 0b00100000010011100000000000000000, :a, :b, :flags15

    # WTF: neg instruction is not differenciated from a rsub :b, :b2, :u6
    #               0b00100bbb11001110FBBB0000001QQQQQ
    #addop32 'neg', 0b00100000110011100000000000100000, :b, :b2, :ccond , :flags15

    add_artihm_op_reduce 'negs',  0b00101, 0b000111
    add_artihm_op_reduce 'negsw', 0b00101, 0b000110

    # nop is an alias over mov null, 0 (mov - [:b, :s12, :flags15])
    addop32 'nop', 0b00100110010010100111000000000000

    add_artihm_op_reduce 'norm',  0b00101, 0b000001
    add_artihm_op_reduce 'normw', 0b00101, 0b001000
    add_artihm_op_reduce 'not',   0b00100, 0b001010

    add_artihm_op 'or', 0b00100, 0b000101

    #                   0b00010bbbssssssssSBBB0aa000111110
    addop32 'prefetch', 0b00010000000000000000000000111110, :@bs9, :wb
    #                   0b00100bbbaa1100000BBBCCCCCC111110
    addop32 'prefetch', 0b00100000001100000000000000111110, :@bextcext, :wb22

    #               0b00100bbb100011011BBBssssssSSSSSS
    addop32 'rcmp', 0b00100000100011011000000000000000, :b, :s12
    #               0b00100bbb110011011BBBCCCCCC0QQQQQ
    addop32 'rcmp', 0b00100000110011011000000000000000, :bext, :cext, :ccond
    #               0b00100bbb110011011BBBuuuuuu1QQQQQ
    addop32 'rcmp', 0b00100000110011011000000000100000, :b, :u6, :ccond

    add_artihm_op_reduce 'rlc',   0b00100, 0b001011
    add_artihm_op_reduce 'rnd16', 0b00101, 0b000011
    add_artihm_op_reduce 'ror',   0b00100, 0b000011

    add_artihm_op 'ror',  0b00101, 0b000011, :extended

    add_artihm_op_reduce 'rrc', 0b00100, 0b000100

    add_artihm_op 'rsub', 0b00100, 0b001110

    addop32 'rtie', 0b00100100011011110000000000111111, :setip, :stopexec

    add_artihm_op_reduce 'sat16', 0b00101, 0b000010

    add_artihm_op 'sbc', 0b00100, 0b000011

    add_artihm_op_reduce 'sexb',  0b00100, 0b000101
    add_artihm_op_reduce 'sexbw', 0b00100, 0b000110

    #                0b00100001011011110000uuuuuu111111
    addop32 'sleep', 0b00100001011011110000000000111111, :u6

    #             0b00100bbb001010110BBBCCCCCCRRRRRR
    addop32 'sr', 0b00100000001010110000000000000000, :bext, :@cext
    #             0b00100110101010110111CCCCCCRRRRRR
    addop32 'sr', 0b00100000101010110000000000000000, :bext, :auxs12
    # WTF: unknown encoding
    addop32 'sr', 0b00100000011010110000000000000000, :bext, :auxs12

    #             0b00011bbbssssssssSBBBCCCCCCDaaZZR
    addop32 'st', 0b00011000000000000000000000000000, :cext, :@bs9, :sz1, :wb3, :cache5

    add_artihm_op 'sub',  0b00100, 0b000010
    add_artihm_op 'sub1', 0b00100, 0b010111
    add_artihm_op 'sub2', 0b00100, 0b011000
    add_artihm_op 'sub3', 0b00100, 0b011001

    # WTF: same encoding as xor instructions
    #add_artihm_op 'subs', 0b00100, 0b000111

    add_artihm_op 'subsdw', 0b00101, 0b101001, :extended

    add_artihm_op_reduce 'swap', 0b00101, 0b000000

    addop32 'swi',  0b00100010011011110000000000111111, :setip, :stopexec
    addop32 'sync', 0b00100011011011110000000000111111

    #              0b00100bbb100010111BBBssssssSSSSSS
    addop32 'tst', 0b00100000100010111000000000000000, :b, :s12
    #              0b00100bbb110010111BBBCCCCCC0QQQQQ
    addop32 'tst', 0b00100000110010111000000000000000, :bext, :cext, :ccond
    #              0b00100bbb110010111BBBuuuuuu1QQQQQ
    addop32 'tst', 0b00100000110010111000000000100000, :b, :u6, :ccond

    add_artihm_op 'xor', 0b00100, 0b000111
  end

  # ARCompact 16-bit instructions
  def init_arc_compact16
    addop16 'abs_s', 0x7811, :cb, :cc
    addop16 'add_s', 0x6018, :ca, :cb, :cc
    addop16 'add_s', 0x7000, :cb, :cb2, :ch
    addop16 'add_s', 0x6800, :cc, :cb, :cu3
    addop16 'add_s', 0xe000, :cb, :cb2, :cu7

    # same encoding as add_s b,b,h
    #addop16 'add_s', 0x70c7, :cb, :cb2, :climm

    addop16 'add_s', 0xc080, :cb, :sp, :cu5ee
    addop16 'add_s', 0xc0a0, :sp, :sp2, :cu5ee
    addop16 'add_s', 0xce00, :cr0, :gp, :cs9
    addop16 'add1_s', 0x7814, :cb, :cb2, :cc
    addop16 'add2_s', 0x7815, :cb, :cb2, :cc
    addop16 'add3_s', 0x7816, :cb, :cb2, :cc
    addop16 'and_s', 0x7804, :cb, :cb2, :cc
    addop16 'asl_s', 0x7818, :cb, :cb2, :cc
    addop16 'asl_s', 0x6810, :cc, :cb, :cu3
    addop16 'asl_s', 0xb800, :cb, :cb2, :cu5
    addop16 'asl_s', 0x781b, :cb, :cc
    addop16 'asr_s', 0x781a, :cb, :cb2, :cc
    addop16 'asr_s', 0x6818, :cc, :cb, :cu3
    addop16 'asr_s', 0xb840, :cb, :cb2, :cu5
    addop16 'asr_s', 0x781c, :cb, :cc
    addop16 'b_s', 0xf000, :cdisps10, :setip, :stopexec
    addop16 'beq_s', 0xf200, :cdisps10, :setip
    addop16 'bne_s', 0xf400, :cdisps10, :setip
    addop16 'bgt_s', 0xf600, :cdisps7, :setip
    addop16 'bge_s', 0xf640, :cdisps7, :setip
    addop16 'blt_s', 0xf680, :cdisps7, :setip
    addop16 'ble_s', 0xf6c0, :cdisps7, :setip
    addop16 'bhi_s', 0xf700, :cdisps7, :setip
    addop16 'bhs_s', 0xf740, :cdisps7, :setip
    addop16 'blo_s', 0xf780, :cdisps7, :setip
    addop16 'bls_s', 0xf7c0, :cdisps7, :setip
    addop16 'bclr_s', 0xb8a0, :cb, :cb2, :cu5
    addop16 'bic_s', 0x7806, :cb, :cb2, :cc
    addop16 'bl_s', 0xf800, :cdisps13, :setip, :saveip, :stopexec
    addop16 'bmsk_s', 0xb8c0, :cb, :cb2, :cu5
    addop16 'breq_s', 0xe800, :cb, :zero, :cdisps8, :setip
    addop16 'brne_s', 0xe880, :cb, :zero, :cdisps8, :setip
    addop16 'brk_s', 0x7fff
    addop16 'bset_s', 0xb880, :cb, :cb2, :cu5
    addop16 'btst_s', 0xb8e0, :cb, :cu5
    addop16 'cmp_s', 0x7010, :cb, :ch
    addop16 'cmp_s', 0xe080, :cb, :cu7

    # encoded over cmp_s b,h
    # addop16 'cmp_s', 0x70d7, :cb, :limm

    addop16 'extb_s', 0x780f, :cb, :cc
    addop16 'extw_s', 0x7810, :cb, :cc
    addop16 'j_s', 0x7800, :@cb, :setip, :stopexec
    addop16 'j_s.d', 0x7820, :@cb, :setip, :stopexec, :delay_slot
    addop16 'j_s', 0x7ee0, :@blink, :setip, :stopexec
    addop16 'j_s.d', 0x7fe0, :@blink, :setip, :stopexec, :delay_slot
    addop16 'jeq_s', 0x7ce0, :@blink, :setip
    addop16 'jne_s', 0x7de0, :@blink, :setip
    addop16 'jl_s', 0x7840, :@cb, :setip, :saveip, :stopexec
    addop16 'jl_s.d', 0x7860, :@cb, :setip, :saveip, :stopexec, :delay_slot
    addop16 'ld_s', 0x6000, :ca, :@cbcc
    addop16 'ldb_s', 0x6008, :ca, :@cbcc
    addop16 'ldw_s', 0x6010, :ca, :@cbcc
    addop16 'ld_s', 0x8000, :cc, :@cbu7
    addop16 'ldb_s', 0x8800, :cc, :@cbu5
    addop16 'ldw_s', 0x9000, :cc, :@cbu6
    addop16 'ldw_s.x', 0x9800, :cc, :@cbu6
    addop16 'ld_s', 0xc000, :cb, :@cspu7
    addop16 'ldb_s', 0xc020, :cb, :@cspu7
    addop16 'ld_s', 0xc800, :cr0, :@gps11
    addop16 'ldb_s', 0xca00, :cr0, :@gps9
    addop16 'ldw_s', 0xcc00, :cr0, :@gps10
    addop16 'ld_s', 0xd000, :cb, :@pclu10

    # FIXME: exact same encoding as asl_s instructions
    #addop16 'lsl_s', 0x7818, :cb, :cb2, :cc
    #addop16 'lsl_s', 0x6810, :cc, :cb, :cu3
    #addop16 'lsl_s', 0xb800, :cb, :cb2, :cu5
    #addop16 'lsl_s', 0x781d, :cb, :cc

    addop16 'lsr_s', 0x7819, :cb, :cb2, :cc
    addop16 'lsr_s', 0xb820, :cb, :cb2, :cu5
    addop16 'lsr_s', 0x781d, :cb, :cc
    addop16 'mov_s', 0x7008, :cb, :ch

    # FIXME: same encoding as previous instruction
    #addop16 'mov_s', 0x70cf, :cb, :limm

    addop16 'mov_s', 0xd800, :cb, :cu8
    addop16 'mov_s', 0x7018, :ch, :cb

    # TODO seems to overlap with previous instruction
    addop16 'mov_s', 0x70df, :zero, :cb
    addop16 'mul64_s', 0x780c, :zero, :cb, :cc
    addop16 'neg_s', 0x7813, :cb, :cc
    addop16 'not_s', 0x7812, :cb, :cc
    addop16 'nop_s',0x78e0
    addop16 'unimp_s', 0x79e0
    addop16 'or_s', 0x7805, :cb, :cb2, :cc
    addop16 'pop_s', 0xc0c1, :cb
    addop16 'pop_s', 0xc0d1, :blink
    addop16 'push_s', 0xc0e1, :cb
    addop16 'push_s', 0xc0f1, :blink
    addop16 'sexb_s', 0x780d, :cb, :cc
    addop16 'sexw_s', 0x780e, :cb, :cc
    addop16 'st_s', 0xc040, :cb, :@cspu7
    addop16 'stb_s', 0xc060, :cb, :@cspu7
    addop16 'st_s', 0xa000, :cc, :@cbu7
    addop16 'stb_s', 0xa800, :cc, :@cbu5
    addop16 'stw_s', 0xb000, :cc, :@cbu6
    addop16 'sub_s', 0x7802, :cb, :cb2, :cc
    addop16 'sub_s', 0x6808, :cc, :cb, :cu3
    addop16 'sub_s', 0xb860, :cb, :cb2, :cu5
    addop16 'sub_s', 0xc1a0, :sp, :sp2, :cu5ee
    addop16 'sub_s.ne', 0x78c0, :cb, :c2, :cb3
    addop16 'trap_s', 0x781E, :cu6, :setip, :stopexec
    addop16 'tst_s', 0x780b, :cb, :cc
    addop16 'xor_s', 0x7807, :cb, :cb2, :cc
  end

end
end
