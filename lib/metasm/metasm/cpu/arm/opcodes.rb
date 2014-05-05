#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm/main'

module Metasm
class ARM
  private

  # ARM MODE

  def addop(name, bin, *args)
    args << :cond if not args.delete :uncond

    suppl = nil
    o = Opcode.new name, bin
    args.each { |a|
      # Should Be One fields
      if a == :sbo16 ; o.bin |= 0b1111 << 16 ; next ; end
      if a == :sbo12 ; o.bin |= 0b1111 << 12 ; next ; end
      if a == :sbo8  ; o.bin |= 0b1111 <<  8 ; next ; end
      if a == :sbo0  ; o.bin |= 0b1111 <<  0 ; next ; end

      o.args << a if @valid_args[a]
      o.props[a] = true if @valid_props[a]
      o.props.update a if a.kind_of?(Hash)
      # special args -> multiple fields
      suppl ||= { :i8_r => [:i8, :rotate], :rm_is => [:rm, :stype, :shifti],
        :rm_rs => [:rm, :stype, :rs], :mem_rn_rm => [:rn, :rm, :rsx, :u],
        :mem_rn_i8_12 => [:rn, :i8_12, :u],
        :mem_rn_rms => [:rn, :rm, :stype, :shifti, :i],
        :mem_rn_i12 => [:rn, :i12, :u]
      }[a]
    }

    args.concat suppl if suppl

    args.each { |a| o.fields[a] = [@fields_mask[a], @fields_shift[a]] if @fields_mask[a] }

    @opcode_list << o
  end

  def addop_data_s(name, op, a1, a2, *h)
    addop name, op | (1 << 25), a1, a2, :i8_r, :rotate, *h
    addop name, op, a1, a2, :rm_is, *h
    addop name, op | (1 << 4), a1, a2, :rm_rs, *h
  end
  def addop_data(name, op, a1, a2)
    addop_data_s name, op << 21, a1, a2
    addop_data_s name+'s', (op << 21) | (1 << 20), a1, a2, :cond_name_off => name.length
  end

  def addop_load_puw(name, op, *a)
    addop name, op, {:baseincr => :post}, :rd, :u, *a
    addop name, op | (1 << 24), :rd, :u, *a
    addop name, op | (1 << 24) | (1 << 21), {:baseincr => :pre}, :rd, :u, *a
  end
  def addop_load_lsh_o(name, op)
    addop_load_puw name, op, :rsz, :mem_rn_rm, {:cond_name_off => 3}
    addop_load_puw name, op | (1 << 22), :mem_rn_i8_12, {:cond_name_off => 3}
  end
  def addop_load_lsh
    op = 9 << 4
    addop_load_lsh_o 'strh',  op | (1 << 5)
    addop_load_lsh_o 'ldrd',  op | (1 << 6)
    addop_load_lsh_o 'strd',  op | (1 << 6) | (1 << 5)
    addop_load_lsh_o 'ldrh',  op | (1 << 20) | (1 << 5)
    addop_load_lsh_o 'ldrsb', op | (1 << 20) | (1 << 6)
    addop_load_lsh_o 'ldrsh', op | (1 << 20) | (1 << 6) | (1 << 5)
  end

  def addop_load_puwt(name, op, *a)
    addop_load_puw name, op, *a
    addop name+'t', op | (1 << 21), {:baseincr => :post, :cond_name_off => name.length}, :rd, :u, *a
  end
  def addop_load_o(name, op, *a)
    addop_load_puwt name, op, :mem_rn_i12, *a
    addop_load_puwt name, op | (1 << 25), :mem_rn_rms, *a
  end
  def addop_load(name, op)
    addop_load_o name, op
    addop_load_o name+'b', op | (1 << 22), :cond_name_off => name.length
  end

  def addop_ldm_go(name, op, *a)
    addop name, op, :rn, :reglist, {:cond_name_off => 3}, *a
  end
  def addop_ldm_w(name, op, *a)
    addop_ldm_go name, op, *a		# base reg untouched
    addop_ldm_go name, op | (1 << 21), {:baseincr => :post}, *a	# base updated
  end
  def addop_ldm_s(name, op)
    addop_ldm_w name, op			# transfer regs
    addop_ldm_w name, op | (1 << 22), :usermoderegs	# transfer usermode regs
  end
  def addop_ldm_p(name, op)
    addop_ldm_s name+'a', op		# target memory included
    addop_ldm_s name+'b', op | (1 << 24)	# target memory excluded, transfer starts at next addr
  end
  def addop_ldm_u(name, op)
    addop_ldm_p name+'d', op		# transfer made downward
    addop_ldm_p name+'i', op | (1 << 23)	# transfer made upward
  end
  def addop_ldm(name, op)
    addop_ldm_u name, op
  end

  # ARMv6 instruction set, aka arm7/arm9
  def init_arm_v6
    @opcode_list = []

    [:baseincr, :cond, :cond_name_off, :usermoderegs, :tothumb, :tojazelle
    ].each { |p| @valid_props[p] = true }

    [:rn, :rd, :rm, :crn, :crd, :crm, :cpn, :reglist, :i24, :rm_rs, :rm_is,
     :i8_r, :mem_rn_rm, :mem_rn_i8_12, :mem_rn_rms, :mem_rn_i12
    ].each { |p| @valid_args[p] = true }

    @fields_mask.update :rn => 0xf, :rd => 0xf, :rs => 0xf, :rm => 0xf,
      :crn => 0xf, :crd => 0xf, :crm => 0xf, :cpn => 0xf,
      :rnx => 0xf, :rdx => 0xf, :rsx => 0xf,
      :shifti => 0x1f, :stype => 3, :rotate => 0xf, :reglist => 0xffff,
      :i8 => 0xff, :i12 => 0xfff, :i24 => 0xff_ffff, :i8_12 => 0xf0f,
      :u => 1, :mask => 0xf, :sbo => 0xf, :cond => 0xf

    @fields_shift.update :rn => 16, :rd => 12, :rs => 8, :rm => 0,
      :crn => 16, :crd => 12, :crm => 0, :cpn => 8,
      :rnx => 16, :rdx => 12, :rsx => 8,
      :shifti => 7, :stype => 5, :rotate => 8, :reglist => 0,
      :i8 => 0, :i12 => 0, :i24 => 0, :i8_12 => 0,
      :u => 23, :mask => 16, :sbo => 12, :cond => 28

    addop_data 'and', 0,  :rd, :rn
    addop_data 'eor', 1,  :rd, :rn
    addop_data 'xor', 1,  :rd, :rn
    addop_data 'sub', 2,  :rd, :rn
    addop_data 'rsb', 3,  :rd, :rn
    addop_data 'add', 4,  :rd, :rn
    addop_data 'adc', 5,  :rd, :rn
    addop_data 'sbc', 6,  :rd, :rn
    addop_data 'rsc', 7,  :rd, :rn
    addop_data_s 'tst', (8  << 21) | (1 << 20), :rdx, :rn
    addop_data_s 'teq', (9  << 21) | (1 << 20), :rdx, :rn
    addop_data_s 'cmp', (10 << 21) | (1 << 20), :rdx, :rn
    addop_data_s 'cmn', (11 << 21) | (1 << 20), :rdx, :rn
    addop_data 'orr', 12, :rd, :rn
    addop_data 'or',  12, :rd, :rn
    addop_data 'mov', 13, :rd, :rnx
    addop_data 'bic', 14, :rd, :rn
    addop_data 'mvn', 15, :rd, :rnx

    addop 'b',  0b1010 << 24, :setip, :stopexec, :i24
    addop 'bl', 0b1011 << 24, :setip, :stopexec, :i24, :saveip
    addop 'bkpt', (0b00010010 << 20) | (0b0111 << 4)		# other fields are available&unused, also cnd != AL is undef
    addop 'blx', 0b1111101 << 25, :setip, :stopexec, :saveip, :tothumb, :h, :uncond, :i24
    addop 'blx', (0b00010010 << 20) | (0b0011 << 4), :setip, :stopexec, :saveip, :tothumb, :rm, :sbo16, :sbo12, :sbo8
    addop 'bx',  (0b00010010 << 20) | (0b0001 << 4), :setip, :stopexec, :rm, :sbo16, :sbo12, :sbo8
    addop 'bxj',  (0b00010010 << 20) | (0b0010 << 4), :setip, :stopexec, :rm, :tojazelle, :sbo16, :sbo12, :sbo8

    addop_load 'str', (1 << 26)
    addop_load 'ldr', (1 << 26) | (1 << 20)
    addop_load_lsh
    addop_ldm 'stm', (1 << 27)
    addop_ldm 'ldm', (1 << 27) | (1 << 20)
    # TODO aliases (http://www.davespace.co.uk/arm/introduction-to-arm/stack.html)
    # fd = full descending  stmfd/ldmfd = stmdb/ldmia
    # ed = empty descending stmed/ldmed = stmda/ldmib
    # fa = full ascending   stmfa/ldmfa = stmib/ldmda
    # ea = empty ascending  stmea/ldmea = stmia/ldmdb

    # TODO mrs, [qus]add/sub*
    addop 'clz',   (0b00010110 << 20) | (0b0001 << 4), :rd, :rm, :sbo16, :sbo8
    addop 'ldrex', (0b00011001 << 20) | (0b1001 << 4), :rd, :rn, :sbo8, :sbo0
    addop 'strex', (0b00011000 << 20) | (0b1001 << 4), :rd, :rm, :rn, :sbo8
    addop 'rev',   (0b01101011 << 20) | (0b0011 << 4), :rd, :rm, :sbo16, :sbo8
    addop 'rev16', (0b01101011 << 20) | (0b1011 << 4), :rd, :rm, :sbo16, :sbo8
    addop 'revsh', (0b01101111 << 20) | (0b1011 << 4), :rd, :rm, :sbo16, :sbo8
    addop 'sel',   (0b01101000 << 20) | (0b1011 << 4), :rd, :rn, :rm, :sbo8

  end



  # THUMB2 MODE

  def addop_t(name, bin, *args)
    o = Opcode.new name, bin
    args.each { |a|
      o.args << a if @valid_args[a]
      o.props[a] = true if @valid_props[a]
      o.props.update a if a.kind_of?(Hash)
    }

    args.each { |a| o.fields[a] = [@fields_mask[a], @fields_shift[a]] if @fields_mask[a] }

    @opcode_list_t << o
  end

  def init_arm_thumb2
    @opcode_list_t = []
    @valid_props_t = {}
    @valid_args_t = {}
    @fields_mask_t = {}
    @fields_shift_t = {}

    [:i16, :i16_3_8, :i16_rd].each { |p| @valid_props_t[p] = true }
    [:i5, :rm, :rn, :rd].each { |p| @valid_args_t[p] = true }
    @fields_mask_t.update :i5 => 0x1f, :i3 => 7, :i51 => 0x5f,
      :rm => 7, :rn => 7, :rd => 7, :rdn => 7, :rdn8 => 7
    @fields_shift_t.update :i5 => 6, :i3 => 6, :i51 => 3,
      :rm => 6, :rn => 3, :rd => 0, :rdn => 0, :rdn8 => 8

    addop_t 'mov', 0b000_00 << 11, :rd, :rm
    addop_t 'lsl', 0b000_00 << 11, :rd, :rm, :i5
    addop_t 'lsr', 0b000_01 << 11, :rd, :rm, :i5
    addop_t 'asr', 0b000_10 << 11, :rd, :rm, :i5

    addop_t 'add', 0b000_1100 << 9, :rd, :rn, :rm
    addop_t 'add', 0b000_1110 << 9, :rd, :rn, :i3
    addop_t 'sub', 0b000_1101 << 9, :rd, :rn, :rm
    addop_t 'sub', 0b000_1111 << 9, :rd, :rn, :i3

    addop_t 'mov', 0b001_00 << 10, :rdn8, :i8
    addop_t 'cmp', 0b001_01 << 10, :rdn8, :i8
    addop_t 'add', 0b001_10 << 10, :rdn8, :i8
    addop_t 'sub', 0b001_11 << 10, :rdn8, :i8

    addop_t 'and', (0b010000 << 10) | ( 0 << 6), :rdn, :rm
    addop_t 'eor', (0b010000 << 10) | ( 1 << 6), :rdn, :rm	# xor
    addop_t 'lsl', (0b010000 << 10) | ( 2 << 6), :rdn, :rm
    addop_t 'lsr', (0b010000 << 10) | ( 3 << 6), :rdn, :rm
    addop_t 'asr', (0b010000 << 10) | ( 4 << 6), :rdn, :rm
    addop_t 'adc', (0b010000 << 10) | ( 5 << 6), :rdn, :rm
    addop_t 'sbc', (0b010000 << 10) | ( 6 << 6), :rdn, :rm
    addop_t 'ror', (0b010000 << 10) | ( 7 << 6), :rdn, :rm
    addop_t 'tst', (0b010000 << 10) | ( 8 << 6), :rdn, :rm
    addop_t 'rsb', (0b010000 << 10) | ( 9 << 6), :rdn, :rm
    addop_t 'cmp', (0b010000 << 10) | (10 << 6), :rdn, :rm
    addop_t 'cmn', (0b010000 << 10) | (11 << 6), :rdn, :rm
    addop_t 'orr', (0b010000 << 10) | (12 << 6), :rdn, :rm	# or
    addop_t 'mul', (0b010000 << 10) | (13 << 6), :rdn, :rm
    addop_t 'bic', (0b010000 << 10) | (14 << 6), :rdn, :rm
    addop_t 'mvn', (0b010000 << 10) | (15 << 6), :rdn, :rm

    addop_t 'add', 0b010001_00 << 8, :rdn, :rm, :dn
    addop_t 'cmp', 0b010001_01 << 8, :rdn, :rm, :dn
    addop_t 'mov', 0b010001_10 << 8, :rdn, :rm, :dn

    addop_t 'bx',  0b010001_110 << 7, :rm
    addop_t 'blx', 0b010001_111 << 7, :rm

    addop_t 'ldr',   0b01001 << 11, :rd, :pc_i8
    addop_t 'str',   0b0101_000 << 9, :rd, :rn, :rm
    addop_t 'strh',  0b0101_001 << 9, :rd, :rn, :rm
    addop_t 'strb',  0b0101_010 << 9, :rd, :rn, :rm
    addop_t 'ldrsb', 0b0101_011 << 9, :rd, :rn, :rm
    addop_t 'ldr',   0b0101_100 << 9, :rd, :rn, :rm
    addop_t 'ldrh',  0b0101_101 << 9, :rd, :rn, :rm
    addop_t 'ldrb',  0b0101_110 << 9, :rd, :rn, :rm
    addop_t 'ldrsh', 0b0101_111 << 9, :rd, :rn, :rm

    addop_t 'str',  0b01100 << 11, :rd, :rn, :i5
    addop_t 'ldr',  0b01101 << 11, :rd, :rn, :i5
    addop_t 'strb', 0b01110 << 11, :rd, :rn, :i5
    addop_t 'ldrb', 0b01111 << 11, :rd, :rn, :i5
    addop_t 'strh', 0b10000 << 11, :rd, :rn, :i5
    addop_t 'ldrh', 0b10001 << 11, :rd, :rn, :i5
    addop_t 'str',  0b10010 << 11, :rd, :sp_i8
    addop_t 'ldr',  0b10011 << 11, :rd, :sp_i8
    addop_t 'adr',  0b10100 << 11, :rd, :pc, :i8
    addop_t 'add',  0b10101 << 11, :rd, :sp, :i8

    # 0b1011 misc
    addop_t 'add',  0b1011_0000_0 << 7, :sp, :i7
    addop_t 'sub',  0b1011_0000_1 << 7, :sp, :i7
    addop_t 'sxth', 0b1011_0010_00 << 6, :rd, :rn
    addop_t 'sxtb', 0b1011_0010_01 << 6, :rd, :rn
    addop_t 'uxth', 0b1011_0010_10 << 6, :rd, :rn
    addop_t 'uxtb', 0b1011_0010_11 << 6, :rd, :rn
    addop_t 'cbz',  0b1011_0001 << 8, :rd, :i51
    addop_t 'cbnz', 0b1011_1001 << 8, :rd, :i51
    addop_t 'push', 0b1011_0100 << 8, :rlist
    addop_t 'push', 0b1011_0101 << 8, :rlist
    addop_t 'pop',  0b1011_1100 << 8, :rlist
    addop_t 'pop',  0b1011_1101 << 8, :rlist
    #addop_t 'unpredictable', 0b1011_0110_0100_0000, :i4
    addop_t 'setendle', 0b1011_0110_0101_0000
    addop_t 'setendbe', 0b1011_0110_0101_1000
    addop_t 'cps', 0b1011_0110_0110_0000
    #addop_t 'unpredictable', 0b1011_0110_0110_1000, :msk_0001_0111
    addop_t 'rev',   0b1011_1010_00 << 6, :rd, :rn
    addop_t 'rev16', 0b1011_1010_01 << 6, :rd, :rn
    addop_t 'revsh', 0b1011_1010_11 << 6, :rd, :rn
    addop_t 'bkpt',  0b1011_1110 << 8, :i8
    addop_t 'it',    0b1011_1111 << 8, :itcond, :itmsk
    addop_t 'nop',   0b1011_1111_0000_0000
    addop_t 'yield', 0b1011_1111_0000_0001
    addop_t 'wfe',   0b1011_1111_0000_0010
    addop_t 'wfi',   0b1011_1111_0000_0011
    addop_t 'sev',   0b1011_1111_0000_0100
    addop_t 'nop',   0b1011_1111_0000_0000, :i4


    addop_t 'stmia', 0b11000 << 11, :rn, :rlist	# stmea
    addop_t 'ldmia', 0b11001 << 11, :rn, :rlist	# ldmfd
    addop_t 'undef', 0b1101_1110 << 8, :i8
    addop_t 'svc',   0b1101_1111 << 8, :i8
    addop_t 'b',     0b1101 << 12, :cond, :i8
    addop_t 'b',     0b11100 << 11, :i11

    # thumb-32
  end

  def init_arm_v6_thumb2
    init_arm_v6
    init_arm_thumb2
  end
  alias init_latest init_arm_v6_thumb2
end
end
