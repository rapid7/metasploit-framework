#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/mips/opcodes'
require 'metasm/decode'

module Metasm
class MIPS
	def build_opcode_bin_mask(op)
		# bit = 0 if can be mutated by an field value, 1 if fixed by opcode
		op.bin_mask = 0
		op.args.each { |f|
			op.bin_mask |= @fields_mask[f] << @fields_shift[f]
		}
		op.bin_mask = 0xffffffff ^ op.bin_mask
	end

	def build_bin_lookaside
		lookaside = Array.new(256) { [] }
		opcode_list.each { |op|
			build_opcode_bin_mask op

			b   = op.bin >> 24
			msk = op.bin_mask >> 24

			for i in b..(b | (255^msk))
				next if i & msk != b & msk
				lookaside[i] << op
			end
		}
		lookaside
	end

	def decode_findopcode(edata)
		return if edata.ptr >= edata.data.length
		# TODO handle relocations !!
		di = DecodedInstruction.new(self)
		val = edata.decode_imm(:u32, @endianness)
		edata.ptr -= 4
		di if di.opcode = @bin_lookaside[val >> 24].find { |op|
			(op.bin & op.bin_mask) == (val & op.bin_mask)
		}
	end

	def decode_instr_op(edata, di)
		# TODO handle relocations !!
		before_ptr = edata.ptr
		op = di.opcode
		di.instruction.opname = op.name
		val = edata.decode_imm(:u32, @endianness)

		field_val = lambda { |f|
			r = (val >> @fields_shift[f]) & @fields_mask[f]
			# XXX do that cleanly (Expr.decode_imm)
			case f
			when :sa, :i16, :it; r = Expression.make_signed(r, 16)
			when :i20; r = Expression.make_signed(r, 20)
			when :i26; r = Expression.make_signed(r, 26)
			else r
			end
		}

		op.args.each { |a|
			di.instruction.args << case a
			when :rs, :rt, :rd; Reg.new field_val[a]
			when :sa, :i16, :i20, :i26, :it; Expression[field_val[a]]
			when :rs_i16; Memref.new Reg.new(field_val[:rs]), Expression[field_val[:i16]]
			when :ft; FpReg.new field_val[a]
			when :idm1, :idb; Expression['unsupported']
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}
		di.bin_length += edata.ptr - before_ptr

		di
	end

	# converts relative branch offsets to absolute addresses
	# else just add the offset +off+ of the instruction + its length (off may be an Expression)
	# assumes edata.ptr points just after the instruction (as decode_instr_op left it)
	# do not call twice on the same di !
	def decode_instr_interpret(di, addr)
		if di.opcode.props[:setip] and di.instruction.args.last.kind_of? Expression and di.opcode.name[0] != ?t
			delta = Expression[di.instruction.args.last, :<<, 2].reduce
			if di.opcode.args.include? :i26
				arg = Expression[[[addr, :+, di.bin_length], :&, 0xfc00_0000], :+, delta].reduce
			else
				arg = Expression[[addr, :+, di.bin_length], :+, delta].reduce
			end
			di.instruction.args[-1] = Expression[arg]
		end

		di
	end

	# hash opname => lambda { |di, *sym_args| binding }
	def backtrace_binding
		@backtrace_binding ||= init_backtrace_binding
	end
	def backtrace_binding=(b) @backtrace_binding = b end

	def init_backtrace_binding
		@backtrace_binding ||= {}
		opcode_list.map { |ol| ol.name }.uniq.each { |op|
			binding = case op
			when 'break'
			when 'bltzal', 'bgezal'; lambda { |di, *a|
				# XXX $ra is set only if branch is taken...
				{ :$ra => Expression[Expression[di.address, :+, 2*di.bin_length].reduce] }
			}
			when 'nop', 'j', 'jr', /^b/; lambda { |di, *a| {} }
			when 'lui'; lambda { |di, a0, a1| { a0 => Expression[a1, :<<, 16] } }
			when 'add', 'addu', 'addi', 'addiu'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :+, a2] } }	# XXX addiu $sp, -40h should be addiu $sp, 0xffc0 from the books, but..
			when 'sub', 'subu'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :-, a2] } }
			when 'slt', 'slti'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :<, a2] } }
			when 'and', 'andi'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :&, a2] } }
			when 'or', 'ori';   lambda { |di, a0, a1, a2|   { a0 => Expression[a1, :|, a2] } }
			when 'nor'; lambda { |di, a0, a1, a2| { a0 => Expression[:~, [a1, :|, a2]] } }
			when 'xor'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :^, a2] } }
			when 'sll', 'sllv'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :>>, a2] } }
			when 'srl', 'srlv', 'sra', 'srav'; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :<<, a2] } }	# XXX sign-extend
			when 'lw';        lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when 'sw';        lambda { |di, a0, a1| { a1 => Expression[a0] } }
			when 'lh', 'lhu'; lambda { |di, a0, a1| { a0 => Expression[a1] } }	# XXX sign-extend
			when 'sh';        lambda { |di, a0, a1| { a1 => Expression[a0] } }
			when 'lb', 'lbu'; lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when 'sb';        lambda { |di, a0, a1| { a1 => Expression[a0] } }
			when /^slti?u?/;  lambda { |di, a0, a1, a2| { a0 => Expression[a1, :<, a2] } }	# XXX signedness
			when 'mfhi'; lambda { |di, a0| { a0 => Expression[:hi] } }
			when 'mflo'; lambda { |di, a0| { a0 => Expression[:lo] } }
			when 'mult'; lambda { |di, a0, a1| { :hi => Expression[[a0, :*, a1], :>>, 32], :lo => Expression[[a0, :*, a1], :&, 0xffff_ffff] } }
			when 'div';  lambda { |di, a0, a1| { :hi => Expression[a0, :%, a1], :lo => Expression[a0, :/, a1] } }
			when 'jal', 'jalr'; lambda { |di, a0| { :$ra => Expression[Expression[di.address, :+, 2*di.bin_length].reduce] } }
			when 'li', 'mov'; lambda { |di, a0, a1| { a0 => Expression[a1] } }
			when 'syscall'; lambda { |di, *a| { :$v0 => Expression::Unknown } }
			end

			@backtrace_binding[op] ||= binding if binding
		}
		@backtrace_binding
	end

	def get_backtrace_binding(di)
		a = di.instruction.args.map { |arg|
			case arg
			when Memref; arg.symbolic(di.address)
			when Reg; arg.symbolic
			else arg
			end
		}

		binding = if binding = backtrace_binding[di.instruction.opname]
			binding[di, *a]
		else
			if di.instruction.opname[0] == ?b and di.opcode.props[:setip]
			else
				puts "unknown instruction to emu #{di}" if $VERBOSE
			end
			{}
		end

		binding.delete 0	# allow add $zero, 42 => nop

		binding
	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]

		arg = di.instruction.args.last
		[Expression[
		case arg
		when Memref; Indirection[[arg.base.to_s.to_sym, :+, arg.offset], @size/8, di.address]
		when Reg; arg.to_s.to_sym
		else arg
		end]]
	end

	def backtrace_update_function_binding(dasm, faddr, f, retaddrlist, *wantregs)
		retaddrlist.map! { |retaddr| dasm.decoded[retaddr] ? dasm.decoded[retaddr].block.list.last.address : retaddr } if retaddrlist
		b = f.backtrace_binding

		bt_val = lambda { |r|
			next if not retaddrlist
			bt = []
			b[r] = Expression::Unknown	# break recursive dep
			retaddrlist.each { |retaddr|
				bt |= dasm.backtrace(Expression[r], retaddr,
					:include_start => true, :snapshot_addr => faddr, :origin => retaddr)
			}
			b[r] = ((bt.length == 1) ? bt.first : Expression::Unknown)
		}
		wantregs = Reg.i_to_s.values if wantregs.empty?
		wantregs.map { |r| r.to_sym }.each(&bt_val)

		puts "update_func_bind: #{Expression[faddr]} has sp -> #{b[:$sp]}" if not Expression[b[:$sp], :-, :$sp].reduce.kind_of?(::Integer) if $VERBOSE
	end

	def backtrace_is_function_return(expr, di=nil)
		expr.reduce_rec == :$ra
	end

	def backtrace_is_stack_address(expr)
		Expression[expr].expr_externals.include? :$sp
	end

	def replace_instr_arg_immediate(i, old, new)
		i.args.map! { |a|
			case a
			when Expression; a == old ? new : Expression[a.bind(old => new).reduce]
			when Memref
				a.offset = (a.offset == old ? new : Expression[a.offset.bind(old => new).reduce]) if a.offset
				a
			else a
			end
		}
	end

	# make the target of the call know the value of $t9 (specified by the ABI)
	# XXX hackish
	def backtrace_found_result(dasm, di, expr, type, len)
		if di.opcode.name == 'jalr' and di.instruction.args == [:$t9]
			expr = dasm.normalize(expr)
			(dasm.address_binding[expr] ||= {})[:$t9] ||= expr
		end
	end

	def delay_slot(di=nil)
		# branch.*likely has no delay slot
		# bltzal/bgezal are 'link', not 'likely', hence the check for -2
		(di and di.opcode.props[:setip] and (di.opcode.name[-1] != ?l or di.opcode.name[-2] == ?a)) ? 1 : 0
	end

	def disassembler_default_func
		df = DecodedFunction.new
		df.backtrace_binding = %w[v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 t8 t9 at k0 k1].inject({}) { |h, r| h.update "$#{r}".to_sym => Expression::Unknown }
		df.backtrace_binding.update %w[gp sp fp ra s0 s1 s2 s3 s4 s5 s6 s7].inject({}) { |h, r| h.update "$#{r}".to_sym => "$#{r}".to_sym }
		df.backtracked_for = [BacktraceTrace.new(Expression[:$ra], :default, Expression[:$ra], :x)]
		df.btfor_callback = lambda { |dasm, btfor, funcaddr, calladdr|
			if funcaddr != :default
				btfor
			elsif di = dasm.decoded[calladdr] and di.opcode.props[:saveip] and di.instruction.to_s != 'jr $ra'
				btfor
			else []
			end
		}
		df
	end
end
end
