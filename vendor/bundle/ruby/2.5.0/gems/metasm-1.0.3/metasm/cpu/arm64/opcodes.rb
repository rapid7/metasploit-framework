#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm64/main'

module Metasm
class ARM64
	private

	def addop(name, bin, *args)
		o = Opcode.new name, bin
		args.each { |a|
			o.args << a if @valid_args[a]
			o.props[a] = true if @valid_props[a]
			o.props.update a if a.kind_of?(::Hash)
		}

		args.each { |a| o.fields[a] = [@fields_mask[a], @fields_shift[a]] if @fields_mask[a] }

		@opcode_list << o
	end

	def addop_s31(n, bin, *args)
		addop n, bin, :r_32, *args
		addop n, (1 << 31) | bin, *args
	end

	def addop_s30(n, bin, *args)
		addop n, bin, :r_32, *args
		addop n, (1 << 30) | bin, *args
	end

	def addop_data_shifted(n, bin, *args)
		addop n, bin | (0b00 << 22), :rt, :rn, :rm_lsl_i6, :r_32, *args
		addop n, bin | (0b01 << 22), :rt, :rn, :rm_lsr_i6, :r_32, *args
		addop n, bin | (0b10 << 22), :rt, :rn, :rm_asr_i6, :r_32, *args
		addop n, bin | (0b00 << 22) | (1 << 31), :rt, :rn, :rm_lsl_i5, *args
		addop n, bin | (0b01 << 22) | (1 << 31), :rt, :rn, :rm_lsr_i5, *args
		addop n, bin | (0b10 << 22) | (1 << 31), :rt, :rn, :rm_asr_i5, *args
	end

	def addop_data_imm(n, bin, *args)
		addop n, bin, :rt, :rn, :bitmask_imm, :bitmask_s, :bitmask_r, *args
		addop n, bin | (1 << 31), :rt, :rn, :bitmask_imm, :bitmask_n, :bitmask_s, :bitmask_r,  *args
	end

	def addop_bitfield(n, bin, *args)
		addop n, bin, :rt, :rn, :bitmask, :bitmask_s, :bitmask_r, *args
		addop n, bin | (1 << 31) | (1 << 22), :rt, :rn, :bitmask, :bitmask_s, :bitmask_r,  *args
	end

	# official name => usual name
	OP_DATA_ALIAS = { 'bic' => 'andn', 'orr' => 'or', 'eor' => 'xor' }
	def addop_data_shifted_alias(n, bin, *args)
		if a = OP_DATA_ALIAS[n]
			addop_data_shifted a, bin, *args
		end
		addop_data_shifted n, bin, *args
	end

	def addop_data_imm_alias(n, bin, *args)
		if a = OP_DATA_ALIAS[n]
			addop_data_imm a, bin, *args
		end
		addop_data_imm n, bin, *args
	end

	def addop_store(n, bin, *args)
		addop_s30 n, bin | (0b01 << 10), :rt, :m_rn_s9, :mem_incr => :post
		addop_s30 n, bin | (0b11 << 10), :rt, :m_rn_s9, :mem_incr => :pre
		addop_s30 n, bin | (1 << 21) | (0b10 << 10) | (1 << 14), :rt, :m_rm_extend
		addop_s30 n, bin | (1 << 24), :rt, :m_rn_u12
	end

	OP_CC = %w[eq ne cs cc  mi pl vs vc  hi ls ge lt  gt le al al2]
	def addop_cc(n, bin, *args)
		OP_CC.each_with_index { |e, i|
			args << :stopexec if e == 'al' and args.include?(:setip)
			addop n+e, bin | i, *args
		}
	end

	public
	# ARMv8 64-bits instruction set, aka AArch64
	def init_arm_v8
		@opcode_list = []

		[:stopexec, :setip, :saveip,
		 :r_z,		# reg nr31 = flag ? zero : sp
		 :r_32,		# reg size == 32bit
		 :mem_incr,	# mem dereference is pre/post-increment
		 :mem_sz,	# point to uint32 => 4
		 :pcrel,	# immediate value is pc-relative
		 :pcrel_page,	# immediate value is a page offset, pc-relative
		].each { |p| @valid_props[p] = true }

		[:rn, :rt, :rt2, :rm,
		 :rm_lsl_i6, :rm_lsr_i6, :rm_asr_i6,
		 :rm_lsl_i5, :rm_lsr_i5, :rm_asr_i5,
		 :m_rm_extend, :rm_extend_i3,
		 :i14_5, :i16_5, :il18_5, :i19_5, :i26_0, :i12_10_s1,
		 :i19_5_2_29,
		 :m_rn_s7, :m_rn_s9, :m_rn_u12,
		 :bitmask, :bitmask_imm, :cond_12,
		].each { |p| @valid_args[p] = true }

		@fields_mask.update :rn => 0x1f, :rt => 0x1f, :rt2 => 0x1f, :rm => 0x1f,
			:rm_lsl_i6 => 0x7ff, :rm_lsr_i6 => 0x7ff, :rm_asr_i6 => 0x7ff,
			:rm_lsl_i5 => 0x7df, :rm_lsr_i5 => 0x7df, :rm_asr_i5 => 0x7df,
			:m_rm_extend => ((0x1f << 11) | (0xb << 7) | 0x1f), :rm_extend_i3 => 0x7ff,
			:i14_5 => 0x3fff, :i16_5 => 0xffff, :il18_5 => 0x3ffff, :i26_0 => 0x3ffffff,
			:i12_10_s1 => 0x3fff, :i6_10 => 0x3f,
			:s7_15 => 0x7f, :s9_12 => 0x1ff, :u12_10 => 0xfff,
			:i19_5 => 0x7ffff, :i2_29 => 3,
			:i19_5_2_29 => 0x60ffffe0, :cond_12 => 0xf,
			:bitmask_n => 1, :bitmask_s => 0x3f, :bitmask_r => 0x3f,
			:regextend_13 => 7, :i1_12 => 1, :i3_10 => 7,
			:m_rn_s7  => ((0x7f << 10) | 0x1f),
			:m_rn_s9  => ((0x1ff << 7) | 0x1f),
			:m_rn_u12 => ((0xfff << 5) | 0x1f)

		@fields_shift.update :rn => 5, :rt => 0, :rt2 => 10, :rm => 16,
			:rm_lsl_i6 => 10, :rm_lsr_i6 => 10, :rm_asr_i6 => 10,
			:rm_lsl_i5 => 10, :rm_lsr_i5 => 10, :rm_asr_i5 => 10,
			:m_rm_extend => 5, :rm_extend_i3 => 10,
			:i14_5 => 5, :i16_5 => 5, :il18_5 => 5, :i26_0 => 0,
			:i12_10_s1 => 10, :i6_10 => 10,
			:s7_15 => 15, :s9_12 => 12, :u12_10 => 10,
			:i19_5 => 5, :i2_29 => 29,
			:i19_5_2_29 => 0, :cond_12 => 12,
			:bitmask_n => 22, :bitmask_s => 10, :bitmask_r => 16,
			:regextend_13 => 13, :i1_12 => 12, :i3_10 => 10,
			:m_rn_s7 => 5, :m_rn_s9 => 5, :m_rn_u12 => 5

		addop 'adr',  1 << 28, :rt, :i19_5_2_29, :pcrel
		addop 'adrp',(1 << 28) | (1 << 31), :rt, :i19_5_2_29, :pcrel_page

		addop_s31 'cbz',  0b0110100 << 24, :rt, :i19_5, :setip
		addop_s31 'cbnz', 0b0110101 << 24, :rt, :i19_5, :setip
		addop_cc 'b', 0b0101010 << 25, :i19_5, :setip

		addop_s31 'mov', (0b01_01010_00_0 << 21) | (0b11111 << 5), :rt, :rm, :r_z  	# alias for orr rt, 0, rm
		addop_data_shifted_alias 'and',  0b00_01010_00_0 << 21
		addop_data_shifted_alias 'bic',  0b00_01010_00_1 << 21	# and not
		addop_data_shifted_alias 'orr',  0b01_01010_00_0 << 21
		addop_data_shifted_alias 'orn',  0b01_01010_00_1 << 21	# or not
		addop_data_shifted_alias 'eor',  0b10_01010_00_0 << 21
		addop_data_shifted_alias 'eorn', 0b10_01010_00_1 << 21
		addop_data_shifted_alias 'ands', 0b11_01010_00_0 << 21, :r_z	# same as and + set flags
		addop_data_shifted_alias 'bics', 0b11_01010_00_1 << 21, :r_z	# same as bic + set flags

		addop 'cmp', (0b11_01011_00_0 << 21) | (0b11111 << 0) | (0b00 << 22), :rn, :rm_lsl_i6, :r_32, :r_z # alias for subs 0, rn, rm
		addop 'cmp', (0b11_01011_00_0 << 21) | (0b11111 << 0) | (0b01 << 22), :rn, :rm_lsr_i6, :r_32, :r_z
		addop 'cmp', (0b11_01011_00_0 << 21) | (0b11111 << 0) | (0b10 << 22), :rn, :rm_asr_i6, :r_32, :r_z
		addop 'cmp', (0b11_01011_00_0 << 21) | (0b11111 << 0) | (0b00 << 22) | (1 << 31), :rn, :rm_lsl_i5, :r_z
		addop 'cmp', (0b11_01011_00_0 << 21) | (0b11111 << 0) | (0b01 << 22) | (1 << 31), :rn, :rm_lsr_i5, :r_z
		addop 'cmp', (0b11_01011_00_0 << 21) | (0b11111 << 0) | (0b10 << 22) | (1 << 31), :rn, :rm_asr_i5, :r_z
		addop_s31 'negs', (0b11_01011_00_0 << 21) | (0b11111 << 5), :rt, :rm, :r_z  	# alias for subs rt, 0, rm
		addop_data_shifted_alias 'add', 0b00_01011_00_0 << 21
		addop_data_shifted_alias 'adds',0b01_01011_00_0 << 21, :r_z
		addop_data_shifted_alias 'sub', 0b10_01011_00_0 << 21
		addop_data_shifted_alias 'subs',0b11_01011_00_0 << 21, :r_z

		addop_s31 'add', 0b00_01011_00_1 << 21, :rt, :rn, :rm_extend_i3
		addop_s31 'adds',0b01_01011_00_1 << 21, :rt, :rn, :rm_extend_i3
		addop_s31 'sub', 0b10_01011_00_1 << 21, :rt, :rn, :rm_extend_i3
		addop_s31 'subs',0b11_01011_00_1 << 21, :rt, :rn, :rm_extend_i3

		addop_data_imm_alias 'and', 0b00_100100 << 23
		addop_data_imm_alias 'orr', 0b01_100100 << 23
		addop_data_imm_alias 'eor', 0b10_100100 << 23
		addop_data_imm_alias 'ands',0b11_100100 << 23, :r_z

		addop 'svc',   (0b11010100 << 24) | (0b000 << 21) | (0b00001), :i16_5
		addop 'hvc',   (0b11010100 << 24) | (0b000 << 21) | (0b00010), :i16_5, :stopexec
		addop 'smc',   (0b11010100 << 24) | (0b000 << 21) | (0b00011), :i16_5, :stopexec
		addop 'brk',   (0b11010100 << 24) | (0b001 << 21) | (0b00000), :i16_5, :stopexec
		addop 'hlt',   (0b11010100 << 24) | (0b010 << 21) | (0b00000), :i16_5, :stopexec
		addop 'dcps1', (0b11010100 << 24) | (0b101 << 21) | (0b00001), :i16_5, :stopexec
		addop 'dcps2', (0b11010100 << 24) | (0b101 << 21) | (0b00010), :i16_5, :stopexec
		addop 'dcps3', (0b11010100 << 24) | (0b101 << 21) | (0b00011), :i16_5, :stopexec

		addop_s31 'tbz', (0b0110110 << 24), :rt, :i14_5

		addop 'b',   (0b000101 << 26), :i26_0, :setip, :stopexec
		addop 'bl',  (0b100101 << 26), :i26_0, :setip, :stopexec, :saveip
		addop 'br',  (0b1101011 << 25) | (0b0000 << 21) | (0b11111 << 16), :rn, :setip, :stopexec
		addop 'blr', (0b1101011 << 25) | (0b0001 << 21) | (0b11111 << 16), :rn, :setip, :stopexec, :saveip
		addop 'ret', (0b1101011 << 25) | (0b0010 << 21) | (0b11111 << 16) | (0b11110 << 5), :setip, :stopexec
		addop 'ret', (0b1101011 << 25) | (0b0010 << 21) | (0b11111 << 16), :rn, :setip, :stopexec
		addop 'eret',(0b1101011 << 25) | (0b0100 << 21) | (0b11111 << 16) | (0b11111 << 5), :setip, :stopexec
		addop 'drps',(0b1101011 << 25) | (0b0101 << 21) | (0b11111 << 16) | (0b11111 << 5), :setip, :stopexec

		addop_s31 'mov',  (0b0010001 << 24), :rt, :rn			# alias for add rt, rn, 0
		addop_s31 'add',  (0b0010001 << 24), :rt, :rn, :i12_10_s1
		addop_s31 'adds', (0b0110001 << 24), :rt, :rn, :i12_10_s1
		addop_s31 'sub',  (0b1010001 << 24), :rt, :rn, :i12_10_s1
		addop_s31 'subs', (0b1110001 << 24), :rt, :rn, :i12_10_s1

		addop_s31 'movn', (0b00100101 << 23), :rt, :il18_5
		addop_s31 'mov',  (0b10100101 << 23), :rt, :i16_5	# alias movz rt, i16 LSL 0
		addop_s31 'movz', (0b10100101 << 23), :rt, :il18_5
		addop_s31 'movk', (0b11100101 << 23), :rt, :il18_5

		addop_store 'str',   (0b10_111_0_00_00 << 22)
		addop_store 'ldr',   (0b10_111_0_00_01 << 22)
		addop_store 'ldrsw', (0b10_111_0_00_10 << 22)
		addop_store 'strb',  (0b00_111_0_00_00 << 22)
		addop_store 'ldrb',  (0b00_111_0_00_01 << 22)
		addop_s31 'stp',  0b00_101_0_001_0 << 22, :rt, :rt2, :m_rn_s7, :mem_incr => :post
		addop_s31 'stp',  0b00_101_0_011_0 << 22, :rt, :rt2, :m_rn_s7, :mem_incr => :pre
		addop_s31 'stp',  0b00_101_0_010_0 << 22, :rt, :rt2, :m_rn_s7
		addop_s31 'ldp',  0b00_101_0_001_1 << 22, :rt, :rt2, :m_rn_s7, :mem_incr => :post
		addop_s31 'ldp',  0b00_101_0_011_1 << 22, :rt, :rt2, :m_rn_s7, :mem_incr => :pre
		addop_s31 'ldp',  0b00_101_0_010_1 << 22, :rt, :rt2, :m_rn_s7

		addop_s31 'csel',  (0b0011010100 << 21) | (0b00 << 10), :rt, :rn, :rm, :cond_12, :r_z
		addop_s31 'csinc', (0b0011010100 << 21) | (0b01 << 10), :rt, :rn, :rm, :cond_12, :r_z
		addop_s31 'csinv', (0b1011010100 << 21) | (0b00 << 10), :rt, :rn, :rm, :cond_12, :r_z
		addop_s31 'csneg', (0b1011010100 << 21) | (0b01 << 10), :rt, :rn, :rm, :cond_12, :r_z

		addop_bitfield 'sbfm', 0b00_100110 << 23
		addop_bitfield 'bfm',  0b01_100110 << 23
		addop_bitfield 'ubfm', 0b10_100110 << 23
	end

	alias init_latest init_arm_v8
end
end
