#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
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
		@opcode_list.each { |op|
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

		field_val = proc { |f|
			r = (val >> @fields_shift[f]) & @fields_mask[f]
			# XXX do that cleanly (Expr.decode_imm)
			case f
			when :sa, :i16, :it
				((r >> 15) == 1) ? (r - (1 << 16)) : r
			when :i20
				((r >> 19) == 1) ? (r - (1 << 20)) : r
			when :i26
				((r >> 25) == 1) ? (r - (1 << 26)) : r
			else r
			end
		}

		op.args.each { |a|
			di.instruction.args << case a
			when :rs, :rt, :rd
				Reg.new field_val[a]
			when :sa, :i16, :i20, :i26, :it
				Expression[field_val[a]]
			when :rs_i16
				Memref.new Reg.new(field_val[:rs]), Expression[field_val[:i16]]
			when :ft
				FpReg.new field_val[a]
			when :idm1, :idb
				Expression['unsupported']
			else
				raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
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
			arg = Expression[[addr, :+, di.bin_length], :+, delta].reduce
			di.instruction.args[-1] = Expression[arg]
		end

		di
	end

	def backtrace_binding(di)
		a = di.instruction.args.map { |arg|
			case arg
			when Memref
				arg.symbolic(di.address)
			when Reg
				arg.symbolic
			else
				arg
			end
		}

		binding =
		case op = di.opcode.name
		when 'nop', 'j', 'jr'
			{}
		when 'lui'
			{ a[0] => Expression[a[1], :<<, 16] }
		when 'add', 'addu', 'addi', 'addiu'
			{ a[0] => Expression[a[1], :+, a[2]] }	# XXX addiu $sp, -40h should be addiu $sp, 0xffc0 from the books, but..
		when 'sub', 'subu'
			{ a[0] => Expression[a[1], :-, a[2]] }
		when 'slt', 'slti'
			{ a[0] => Expression[a[1], :<, a[2]] }
		when 'and', 'andi'
			{ a[0] => Expression[a[1], :&, a[2]] }
		when 'or', 'ori'
			{ a[0] => Expression[a[1], :|, a[2]] }
		when 'nor'
			{ a[0] => Expression[:~, [a[1], :|, a[2]]] }
		when 'xor'
			{ a[0] => Expression[a[1], :^, a[2]] }
		when 'sll'
			{ a[0] => Expression[a[1], :>>, a[2]] }
		when 'srl','sra'
			{ a[0] => Expression[a[1], :<<, a[2]] }	# XXX sign-extend
		when 'lw'
			{ a[0] => Expression[a[1]] }
		when 'sw'
			{ a[1] => Expression[a[0]] }
		when 'lh', 'lhu'
			{ a[0] => Expression[a[1]] }	# XXX sign-extend
		when 'sh'
			{ a[1] => Expression[a[0]] }
		when 'lb', 'lbu'
			{ a[0] => Expression[a[1]] }
		when 'sb'
			{ a[1] => Expression[a[0]] }
		when 'mfhi'
			{ a[0] => Expression[:hi] }
		when 'mflo'
			{ a[0] => Expression[:lo] }
		when 'mult'
			{ :hi => Expression[[a[0], :*, a[1]], :>>, 32], :lo => Expression[[a[0], :*, a[1]], :&, 0xffff_ffff] }
		when 'div'
			{ :hi => Expression[a[0], :%, a[1]], :lo => Expression[a[0], :/, a[1]] }
		when 'jalr'
			{ :$ra => Expression[Expression[di.address, :+, 2*di.bin_length].reduce] }
		else
			if op[0] == ?b and di.opcode.props[:setip]
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
		when Memref
			Indirection[[arg.base.to_s.to_sym, :+, arg.offset], @size/8, di.address]
		when Reg
			arg.to_s.to_sym
		else
			arg
		end]]
	end

	def backtrace_update_function_binding(dasm, faddr, f, retaddrlist)
		retaddrlist.map! { |retaddr| dasm.decoded[retaddr] ? dasm.decoded[retaddr].block.list.last.address : retaddr }
		b = f.backtrace_binding
		
		bt_val = proc { |r|
			bt = []
			retaddrlist.each { |retaddr|
				bt |= dasm.backtrace(Expression[r], retaddr,
					:include_start => true, :snapshot_addr => faddr, :origin => retaddr)
			}
			b[r] = ((bt.length == 1) ? bt.first : Expression::Unknown)
		}
		Reg.i_to_s.values.map { |r| r.to_sym }.each(&bt_val)
		
		puts "update_func_bind: #{Expression[faddr]} has sp -> #{b[:$sp]}" if not f.need_finalize and not Expression[b[:$sp], :-, :$sp].reduce.kind_of?(::Integer) if $VERBOSE
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
                        when Expression
							a == old ? new : Expression[a.bind(old => new).reduce]
                        when Memref
                                a.offset = (a.offset == old ? new : Expression[a.offset.bind(old => new).reduce]) if a.offset
                                a
                        else
							a
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

	# branch.*likely has no delay slot
	def delay_slot(di)
		(di.opcode.name[0] == ?b and di.opcode.name[-1] == ?l) ? 0 : 1
	end

	def disassembler_default_func
		df = DecodedFunction.new
		# from http://www.cs.rpi.edu/~chrisc/COURSES/CSCI-4250/FALL-2004/MIPS-regs.html
		df.backtrace_binding = %w[v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 t8 t9 at k0 k1].inject({}) { |h, r| h.update "$#{r}".to_sym => Expression::Unknown }
		df.backtracked_for = [BacktraceTrace.new(Expression[:$ra], :default, Expression[:$ra], :x)]
		df.btfor_callback = proc { |dasm, btfor, funcaddr, calladdr|
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
