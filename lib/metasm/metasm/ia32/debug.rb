#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/opcodes'

module Metasm
class Ia32
	def dbg_register_pc
		@dbg_register_pc ||= :eip
	end
	def dbg_register_flags
		@dbg_register_flags ||= :eflags
	end

	def dbg_register_list 
		@dbg_register_list ||= [:eax, :ebx, :ecx, :edx, :esi, :edi, :ebp, :esp, :eip]
	end

	def dbg_register_size
		@dbg_register_size ||= Hash.new(32).update(:cs => 16, :ds => 16, :es => 16, :fs => 16, :gs => 16)
	end

	def dbg_flag_list
		@dbg_flag_list ||= [:c, :p, :a, :z, :s, :i, :d, :o]
	end

	DBG_FLAGS = { :c => 0, :p => 2, :a => 4, :z => 6, :s => 7, :t => 8, :i => 9, :d => 10, :o => 11 }
	def dbg_get_flag(dbg, f)
		(dbg.get_reg_value(dbg_register_flags) >> DBG_FLAGS[f]) & 1
	end
	def dbg_set_flag(dbg, f)
		fl = dbg.get_reg_value(dbg_register_flags)
		fl |= 1 << DBG_FLAGS[f]
		dbg.set_reg_value(dbg_register_flags, fl)
	end
	def dbg_unset_flag(dbg, f)
		fl = dbg.get_reg_value(dbg_register_flags)
		fl &= ~(1 << DBG_FLAGS[f])
		dbg.set_reg_value(dbg_register_flags, fl)
	end

	def dbg_enable_singlestep(dbg)
		dbg_set_flag(dbg, :t)
	end
	def dbg_disable_singlestep(dbg)
		dbg_unset_flag(dbg, :t)
	end

	def dbg_enable_bp(dbg, addr, bp)
		case bp.type
		when :bpx; dbg_enable_bpx( dbg, addr, bp)
		else       dbg_enable_bphw(dbg, addr, bp)
		end
	end

	def dbg_disable_bp(dbg, addr, bp)
		case bp.type
		when :bpx; dbg_disable_bpx( dbg, addr, bp)
		else       dbg_disable_bphw(dbg, addr, bp)
		end
	end

	def dbg_enable_bpx(dbg, addr, bp)
		bp.previous ||= dbg.memory[addr, 1]
		dbg.memory[addr, 1] = "\xcc"
	end

	def dbg_disable_bpx(dbg, addr, bp)
		dbg.memory[addr, 1] = bp.previous
	end

	# allocate a debug register for a hwbp by checking the list of hwbp existing in dbg
	def dbg_alloc_bphw(dbg, addr, bp)
		if not bp.previous.kind_of? ::Integer
			may = [0, 1, 2, 3]
			dbg.breakpoint.each { |a, b| may.delete b.previous if b.type == :hw }
			raise 'alloc_bphw: no free debugregister' if may.empty?
			bp.previous = may.first
		end
		bp.mtype ||= :x
		bp.mlen ||= 1
		bp.previous
	end

	def dbg_enable_bphw(dbg, addr, bp)
		nr = dbg_alloc_bphw(dbg, addr, bp)
		dr7 = dbg.get_reg_value(:dr7)
		l = { 1 => 0, 2 => 1, 4 => 3, 8 => 2 }[bp.mlen]
		rw = { :x => 0, :w => 1, :r => 3 }[bp.mtype]
		raise "enable_bphw: invalid breakpoint #{bp.inspect}" if not l or not rw
		dr7 &= ~((15 << (16+4*nr)) | (3 << (2*nr)))	# clear
		dr7 |= ((l << 2) | rw) << (16+4*nr)	# set drN len/rw
		dr7 |= 3 << (2*nr)	# enable global/local drN

		dbg.set_reg_value("dr#{nr}".to_sym, addr)
		dbg.set_reg_value(:dr7, dr7)
	end

	def dbg_disable_bphw(dbg, addr, bp)
		nr = dbg_alloc_bphw(dbg, addr, bp)
		dr7 = dbg.get_reg_value(:dr7)
		dr7 &= ~(3 << (2*nr))
		dbg.set_reg_value(:dr7, dr7)
	end

	def dbg_check_pre_run(dbg)
		if dbg[:dr6] == 0 and dbg[:dr7] == 0
			dbg[:dr7] = 0x10000	# some OS (eg Windows) only return dr6 if dr7 != 0
		end
		dbg[:dr6] = 0
	end

	def dbg_check_post_run(dbg)
		if dbg.state == :stopped and not dbg.info
			eip = dbg.pc
			if dbg.breakpoint[eip-1] and dbg.memory[eip-1, 1] == "\xcc" and dbg[:dr6] & 0x4000 == 0
				# we may get there by singlestepping a branch just over the \xcc
				# the dr6 check should take care of that
				# we probably got there by hitting the bp, so we need to fix eip
				# another exception would presumably have @info not nil
				dbg.pc = eip-1
			end
		end
	end

	def dbg_need_stepover(dbg, addr, di)
		di and ((di.instruction.prefix and di.instruction.prefix[:rep]) or di.opcode.props[:saveip])
	end

	def dbg_end_stepout(dbg, addr, di)
		di and di.opcode.name == 'ret'
	end

	# return (yield) a list of [addr, symbolic name]
	def dbg_stacktrace(dbg, rec=500)
		ret = []
		s = dbg.addrname!(dbg.pc)
		yield(dbg.pc, s) if block_given?
		ret << [dbg.pc, s]
		fp = dbg.get_reg_value(dbg_register_list[6])
		stack = dbg.get_reg_value(dbg_register_list[7]) - 8
		while fp > stack and fp <= stack+0x10000 and rec != 0
			rec -= 1
			ra = dbg.resolve_expr Indirection[fp+4, 4]
			s = dbg.addrname!(ra)
			yield(ra, s) if block_given?
			ret << [ra, s]
			stack = fp	# ensure we walk the stack upwards
			fp = dbg.resolve_expr Indirection[fp, 4]
		end
		ret
	end

	# retrieve the current function return address
	# to be called only on entry of the subfunction
	def dbg_func_retaddr(dbg)
		dbg.memory_read_int(:esp)
	end
	def dbg_func_retaddr_set(dbg, ret)
		dbg.memory_write_int(:esp, ret)
	end

	# retrieve the current function arguments
	# only valid at function entry
	def dbg_func_arg(dbg, argnr)
		dbg.memory_read_int(Expression[:esp, :+, 4*argnr])
	end
	def dbg_func_arg_set(dbg, argnr, arg)
		dbg.memory_write_int(Expression[:esp, :+, 4*argnr], arg)
	end
end
end
