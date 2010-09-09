#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/arm/main'

module Metasm
class ARM
	private
	def addop(name, bin, *args)
		args << :cond if not args.delete :uncond

		o = Opcode.new name, bin
		o.args.concat(args & @valid_args)
		(args & @valid_props).each { |p| o.props[p] = true }
		args.grep(Hash).each { |h| o.props.update h }

		# special args -> multiple fields
		case (o.args & [:i8_r, :rm_is, :rm_rs, :mem_rn_rm, :mem_rn_i8_12, :mem_rn_rms, :mem_rn_i12]).first
		when :i8_r; args << :i8 << :rotate
		when :rm_is; args << :rm << :stype << :shifti
		when :rm_rs; args << :rm << :stype << :rs
		when :mem_rn_rm; args << :rn << :rm << :rsx << :u
		when :mem_rn_i8_12; args << :rn << :i8_12 << :u
		when :mem_rn_rms; args << :rn << :rm << :stype << :shifti << :u
		when :mem_rn_i12; args << :rn << :i12 << :u
		end

		(args & @fields_mask.keys).each { |f|
			o.fields[f] = [@fields_mask[f], @fields_shift[f]]
		}

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
		@valid_props << :baseincr << :cond << :cond_name_off << :usermoderegs <<
				:tothumb << :tojazelle
		@valid_args.concat [:rn, :rd, :rm, :crn, :crd, :crm, :cpn, :reglist, :i24,
			:rm_rs, :rm_is, :i8_r, :mem_rn_rm, :mem_rn_i8_12, :mem_rn_rms, :mem_rn_i12]
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
		addop_data 'tst', 8,  :rdx, :rn
		addop_data 'teq', 9,  :rdx, :rn
		addop_data 'cmp', 10, :rdx, :rn
		addop_data 'cmn', 11, :rdx, :rn
		addop_data 'orr', 12, :rd, :rn
		addop_data 'or',  12, :rd, :rn
		addop_data 'mov', 13, :rd, :rnx
		addop_data 'bic', 14, :rd, :rn
		addop_data 'mvn', 15, :rd, :rnx
		
		addop 'b',  0b1010 << 24, :setip, :stopexec, :i24
		addop 'bl', 0b1011 << 24, :setip, :stopexec, :i24, :saveip
		addop 'bkpt', (0b00010010 << 20) | (0b0111 << 4)		# other fields are available&unused, also cnd != AL is undef
		addop 'blx', 0b1111101 << 25, :setip, :stopexec, :saveip, :tothumb, :h, :nocond, :i24
		addop 'blx', (0b00010010 << 20) | (0b0011 << 4), :setip, :stopexec, :saveip, :tothumb, :rm
		addop 'bx',  (0b00010010 << 20) | (0b0001 << 4), :setip, :stopexec, :rm
		addop 'bxj',  (0b00010010 << 20) | (0b0010 << 4), :setip, :stopexec, :rm, :tojazelle

		addop_load 'str', (1 << 26)
		addop_load 'ldr', (1 << 26) | (1 << 20)
		addop_load_lsh
		addop_ldm 'stm', (1 << 27)
		addop_ldm 'ldm', (1 << 27) | (1 << 20)
	end
	alias init_latest init_arm_v6
end
end

__END__
		addop_cond 'mrs',  0b0001000011110000000000000000, :rd
		addop_cond 'msr',  0b0001001010011111000000000000, :rd
		addop_cond 'msrf', 0b0001001010001111000000000000, :rd

		addop_cond 'mul',  0b000000000000001001 << 4, :rd, :rn, :rs, :rm
		addop_cond 'mla',  0b100000000000001001 << 4, :rd, :rn, :rs, :rm

		addop_cond 'swp',   0b0001000000000000000010010000, :rd, :rn, :rs, :rm
		addop_cond 'swpb',  0b0001010000000000000010010000, :rd, :rn, :rs, :rm

		addop_cond 'undef', 0b00000110000000000000000000010000

		addop_cond 'swi', 0b00001111 << 24

		addop_cond 'bkpt',  0b1001000000000000001110000
		addop_cond 'movw',  0b0011 << 24, :movwimm
