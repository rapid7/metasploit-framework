#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/opcodes'
require 'metasm/decode'

module Metasm
	class Ia32
		class ModRM
			def self.decode(edata, byte, endianness, adsz, opsz, seg=nil, regclass=Reg)
				m = (byte >> 6) & 3
				rm = byte & 7

				if m == 3
					return regclass.new(rm, opsz)
				end

				sum = Sum[adsz][m][rm]

				s, i, b, imm = nil
				sum.each { |a|
					case a
					when Integer
						if not b
							b = Reg.new(a, adsz)
						else
							s = 1
							i = Reg.new(a, adsz)
						end

					when :sib
						sib = edata.get_byte.to_i

						ii = ((sib >> 3) & 7)
						if ii != 4
							s = 1 << ((sib >> 6) & 3)
							i = Reg.new(ii, adsz)
						end

						bb = sib & 7
						if bb == 5 and m == 0
							imm = Expression[edata.decode_imm("i#{adsz}".to_sym, endianness)]
					else
						b = Reg.new(bb, adsz)
					end

				when :i8, :i16, :i32
					imm = Expression[edata.decode_imm(a, endianness)]

				end
			}
			
			new adsz, opsz, s, i, b, imm, seg
		end
	end

	class Farptr
		def self.decode(edata, endianness, adsz)
			addr = Expression[edata.decode_imm("u#{adsz}".to_sym, endianness)]
			seg = Expression[edata.decode_imm(:u16, endianness)]
			new seg, addr
		end
	end

	def build_opcode_bin_mask(op)
		# bit = 0 if can be mutated by an field value, 1 if fixed by opcode
		op.bin_mask = Array.new(op.bin.length, 0)
		op.fields.each { |f, (oct, off)|
			op.bin_mask[oct] |= (@fields_mask[f] << off)
		}
		op.bin_mask.map! { |v| 255 ^ v }
	end

	def build_bin_lookaside
		# sets up a hash byte value => list of opcodes that may match
		# opcode.bin_mask is built here
		lookaside = Array.new(256) { [] }
		@opcode_list.each { |op|

			build_opcode_bin_mask op

			b   = op.bin[0]
			msk = op.bin_mask[0]
			
			for i in b..(b | (255^msk))
				next if i & msk != b & msk
				lookaside[i] << op
			end
		}
		lookaside
	end

	def decode_prefix(instr, byte)
		# XXX check multiple occurences ?
		instr.prefix ||= {}
		(instr.prefix[:list] ||= []) << byte

		case byte
		when 0x66
			instr.prefix[:opsz] = true
		when 0x67
			instr.prefix[:adsz] = true
		when 0xF0
			instr.prefix[:lock] = true
		when 0xF2
			instr.prefix[:rep]  = :nz
		when 0xF3
			instr.prefix[:rep]  = :z	# postprocessed by decode_instr
		when 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65
			if byte & 0x40 == 0
				v = (byte >> 3) & 3
			else
				v = byte & 7
			end
			instr.prefix[:seg] = SegReg.new(v)
			
			instr.prefix[:jmphint] = ((byte & 0x10) == 0x10)	
		else
			return false
		end
		true
	end

	# tries to find the opcode encoded at edata.ptr
	# if no match, tries to match a prefix (update di.instruction.prefix)
	# on match, edata.ptr points to the first byte of the opcode (after prefixes)
	def decode_findopcode(edata)
		di = DecodedInstruction.new self
		while edata.ptr < edata.data.length
			pfx = di.instruction.prefix || {}
			return di if di.opcode = @bin_lookaside[edata.data[edata.ptr]].find { |op|
				# fetch the relevant bytes from edata
				bseq = edata.data[edata.ptr, op.bin.length].unpack('C*')

				# check against full opcode mask
				op.bin.zip(bseq, op.bin_mask).all? { |b1, b2, m| b2 and ((b1 & m) == (b2 & m)) } and
				# check special cases
				!(
				  # fail if any of those is true
				  (fld = op.fields[:seg2A]  and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg2A] == 1) or
				  (fld = op.fields[:seg3A]  and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg3A] < 4) or
				  (fld = op.fields[:seg3A] || op.fields[:seg3] and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg3] > 5) or
				  (fld = op.fields[:modrmA] and (bseq[fld[0]] >> fld[1]) & 0xC0 == 0xC0) or
				  (sz  = op.props[:opsz]    and ((pfx[:opsz] and @size != 48-sz) or
					(not pfx[:opsz] and @size != sz))) or
				  (pfx = op.props[:needpfx] and not (pfx[:list] || []).include? pfx)
				 )
			}

			break if not decode_prefix(di.instruction, edata.get_byte)
			di.bin_length += 1
		end
	end

	def decode_instr_op(edata, di)
		before_ptr = edata.ptr
		op = di.opcode
		di.instruction.opname = op.name
		bseq = edata.read(op.bin.length).unpack('C*')		# decode_findopcode ensures that data >= op.length
		pfx = di.instruction.prefix || {}

		field_val = proc { |f|
			if fld = op.fields[f]
				(bseq[fld[0]] >> fld[1]) & @fields_mask[f]
			end
		}

		if field_val[:w] == 0
			opsz = 8
		elsif pfx[:opsz]
			opsz = 48 - @size
		else
			opsz = @size
		end

		if pfx[:adsz]
			adsz = 48 - @size
		else
			adsz = @size
		end
		
		op.args.each { |a|
			mmxsz = ((op.props[:xmmx] && pfx[:opsz]) ? 128 : 64)
			di.instruction.args << case a
			when :reg
				Reg.new     field_val[a], opsz
			when :eeec
				CtrlReg.new field_val[a]
			when :eeed
				DbgReg.new  field_val[a]
			when :seg2, :seg2A, :seg3, :seg3A
				SegReg.new field_val[a]
			when :regfp
				FpReg.new   field_val[a]
			when :regmmx
				SimdReg.new field_val[a], mmxsz
			when :regxmm
				SimdReg.new field_val[a], 128

			when :farptr
				Farptr.decode edata, @endianness, adsz
			when :i8, :u8, :u16
				Expression[edata.decode_imm(a, @endianness)]
			when :i
				Expression[edata.decode_imm("#{op.props[:unsigned_imm] ? 'a' : 'i'}#{opsz}".to_sym, @endianness)]

			when :mrm_imm
				ModRM.decode edata, (adsz == 16 ? 6 : 5), @endianness, adsz, opsz, pfx[:seg]
			when :modrm, :modrmA
				ModRM.decode edata, field_val[a], @endianness, adsz, (op.props[:argsz] || opsz), pfx[:seg]
			when :modrmmmx
				ModRM.decode edata, field_val[:modrm], @endianness, adsz, mmxsz, pfx[:seg], SimdReg
			when :modrmxmm
				ModRM.decode edata, field_val[:modrm], @endianness, adsz, 128, pfx[:seg], SimdReg

			when :imm_val1
				Expression[1]
			when :imm_val3
				Expression[3]
			when :reg_cl
				Reg.new 1, 8
			when :reg_eax
				Reg.new 0, opsz
			when :reg_dx
				Reg.new 2, 16
			when :regfp0
				FpReg.new nil	# implicit?
			else
				raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		di.bin_length += edata.ptr - before_ptr

		if op.name == 'movsx' or op.name == 'movzx'
			if opsz == 8
				di.instruction.args[1].sz = 8
			else
				di.instruction.args[1].sz = 16
			end
			if pfx[:opsz]
				di.instruction.args[0].sz = 48 - @size
			else
				di.instruction.args[0].sz = @size
			end
		end

		pfx.delete :seg
		case r = pfx.delete(:rep)
		when :nz
			if di.opcode.props[:strop]
				pfx[:rep] = 'rep'
			elsif di.opcode.props[:stropz]
				pfx[:rep] = 'repnz'
			end
		when :z
			if di.opcode.props[:stropz]
				pfx[:rep] = 'repz'
			end
		end

		di
	end

	# converts relative jump/call offsets to absolute addresses
	# adds the eip delta to the offset +off+ of the instruction (may be an Expression) + its bin_length
	# do not call twice on the same di !
	def decode_instr_interpret(di, addr)
		if di.opcode.props[:setip] and di.instruction.args.last.kind_of? Expression and di.instruction.opname[0, 3] != 'ret'
			delta = di.instruction.args.last.reduce
			arg = Expression[[addr, :+, di.bin_length], :+, delta].reduce
			di.instruction.args[-1] = Expression[arg]
		end

		di
	end

	# interprets a condition code (in an opcode name) as an expression involving backtracked eflags
	# eflag_p is never computed, and this returns Expression::Unknown for this flag
	# ex: 'z' => Expression[:eflag_z]
	def decode_cc_to_expr(cc)
		case cc
		when 'o'
			Expression[:eflag_o]
		when 'no'
			Expression[:'!', :eflag_o]
		when 'b', 'nae'
			Expression[:eflag_c]
		when 'nb', 'ae'
			Expression[:'!', :eflag_c]
		when 'z', 'e'
			Expression[:eflag_z]
		when 'nz', 'ne'
			Expression[:'!', :eflag_z]
		when 'be', 'na'
			Expression[:eflag_c, :|, :eflag_z]
		when 'nbe', 'a'
			Expression[:'!', [:eflag_c, :|, :eflag_z]]
		when 's'
			Expression[:eflag_s]
		when 'ns'
			Expression[:'!', :eflag_s]
		when 'p', 'pe'
			Expression::Unknown
		when 'np', 'po'
			Expression::Unknown
		when 'l', 'nge'
			Expression[:eflag_s, :'!=', :eflag_o]
		when 'nl', 'ge'
			Expression[:eflag_s, :==, :eflag_o]
		when 'le', 'ng'
			Expression[[:eflag_s, :'!=', :eflag_o], :|, :eflag_z]
		when 'nle', 'g'
			Expression[[:eflag_s, :==, :eflag_o], :&, :eflag_z]
		end
	end

	def backtrace_binding(di)
		a = di.instruction.args.map { |arg|
			case arg
			when ModRM
				arg.symbolic(di.address)
			when Reg, SimdReg
				arg.symbolic
			else
				arg
			end
		}

		# XXX TODO opsz override ?
		opsz = @size
		opsz = 48 - opsz if di.instruction.prefix and di.instruction.prefix[:opsz]
		mask = (1 << opsz)-1	# 32bits => 0xffff_ffff

		binding =
		case op = di.opcode.name
		when 'mov', 'movsx', 'movzx', 'movd', 'movq'
			{ a[0] => Expression[a[1]] }
		when 'lea'
			{ a[0] => a[1].target }
		when 'xchg'
			{ a[0] => Expression[a[1]], a[1] => Expression[a[0]] }
		when 'add', 'sub', 'or', 'xor', 'and', 'pxor', 'adc', 'sbb'
			e_op = { 'add' => :+, 'sub' => :-, 'or' => :|, 'and' => :&, 'xor' => :^, 'pxor' => :^, 'adc' => :+, 'sbb' => :- }[op]
			ret = Expression[a[0], e_op, a[1]]
			ret = Expression[ret, e_op, :eflag_c] if op == 'adc' or op == 'sbb'
			# optimises :eax ^ :eax => 0
			# avoid hiding memory accesses (to not hide possible fault)
			ret = Expression[ret.reduce] if not a[0].kind_of? Indirection
			{ a[0] => ret }
		when 'inc'
			{ a[0] => Expression[a[0], :+, 1] }
		when 'dec'
			{ a[0] => Expression[a[0], :-, 1] }
		when 'not'
			{ a[0] => Expression[a[0], :^, mask] }
		when 'neg'
			{ a[0] => Expression[:-, a[0]] }
		when 'rol', 'ror'
			inv_op = (op[2] == ?r ? :<< : :>>)
			e_op = (op[2] == ?r ? :>> : :<<)
			sz = [a[1], :%, opsz]
			isz = [[opsz, :-, a[1]], :%, opsz]
			# ror a, b  =>  (a >> b) | (a << (32-b))
			{ a[0] => Expression[[[a[0], e_op, sz], :|, [a[0], inv_op, isz]], :&, mask] }
		when 'sar', 'shl', 'sal'
			{ a[0] => Expression[a[0], (op[-1] == ?r ? :>> : :<<), [a[1], :%, opsz]] }
		when 'shr'
			{ a[0] => Expression[[a[0], :&, mask], :>>, [a[1], :%, opsz]] }
		when 'cdq'
			{ :edx => Expression[0xffff_ffff, :*, [[:eax, :>>, opsz-1], :&, 1]] }
		when 'push', 'push.i16'
			{ :esp => Expression[:esp, :-, opsz/8],
			  Indirection[:esp, opsz/8, di.address] => Expression[a[0]] }
		when 'pop'
			{ :esp => Expression[:esp, :+, opsz/8],
			  a[0] => Indirection[:esp, opsz/8, di.address] }
		when 'pushfd'
			# TODO Unknown per bit
			efl = Expression[0x202]
			bts = proc { |pos, v| efl = Expression[efl, :|, [[v, :&, 1], :<<, pos]] }
			bts[0, :eflag_c]
			bts[6, :eflag_z]
			bts[7, :eflag_s]
			bts[11, :eflag_o]
			{ :esp => Expression[:esp, :-, opsz/8], Indirection[:esp, opsz/8, di.address] => efl }
		when 'popfd'
			bt = proc { |pos| Expression[[Indirection[:esp, opsz/8, di.address], :>>, pos], :&, 1] }
			{ :esp => Expression[:esp, :+, opsz/8], :eflag_c => bt[0], :eflag_z => bt[6], :eflag_s => bt[7], :eflag_o => bt[11] }
		when 'sahf'
			bt = proc { |pos| Expression[[:eax, :>>, pos], :&, 1] }
			{ :eflag_c => bt[0], :eflag_z => bt[6], :eflag_s => bt[7] }
		when 'lahf'
			efl = Expression[2]
			bts = proc { |pos, v| efl = Expression[efl, :|, [[v, :&, 1], :<<, pos]] }
			bts[0, :eflag_c]
			#bts[2, :eflag_p]
			#bts[4, :eflag_a]
			bts[6, :eflag_z]
			bts[7, :eflag_s]
			{ :eax => efl }
		when 'pushad'
			ret = {}
			st_off = 0
			[:eax, :ecx, :edx, :ebx, :esp, :ebp, :esi, :edi].reverse_each { |r|
				ret[Indirection[Expression[:esp, :+, st_off].reduce, opsz/8, di.address]] = Expression[r]
				st_off += opsz/8
			}
			ret[:esp] = Expression[:esp, :-, st_off]
			ret
		when 'popad'
			ret = {}
			st_off = 0
			[:eax, :ecx, :edx, :ebx, :esp, :ebp, :esi, :edi].reverse_each { |r|
				ret[r] = Indirection[Expression[:esp, :+, st_off].reduce, opsz/8, di.address]
				st_off += opsz/8
			}
			ret
		when 'call'
			{ :esp => Expression[:esp, :-, opsz/8],
			  Indirection[:esp, opsz/8, di.address] => Expression[Expression[di.address, :+, di.bin_length].reduce] }
		when 'ret'
			{ :esp => Expression[:esp, :+, [opsz/8, :+, a[0] || 0]] }
		when 'loop', 'loopz', 'loopnz'
			{ :ecx => Expression[:ecx, :-, 1] }
		when 'enter'
			depth = a[1].reduce % 32
			b = { Indirection[:esp, opsz/8, di.address] => Expression[:ebp], :ebp => Expression[:esp, :-, opsz/8],
					:esp => Expression[:esp, :-, a[0].reduce + ((opsz/8) * depth)] }
			(1..depth).each { |i| # XXX test me !
				b[Indirection[[:esp, :-, i*opsz/8], opsz/8, di.address]] = Indirection[[:ebp, :-, i*opsz/8], opsz/8, di.address] }
			b
		when 'leave'
			{ :ebp => Indirection[[:ebp], opsz/8, di.address], :esp => Expression[:ebp, :+, opsz/8] }
		when 'aaa'
			{ :eax => Expression::Unknown }
		when 'imul'
			if a[2]
				e = Expression[a[1], :*, a[2]]
			else
				e = Expression[[a[0], :*, a[1]], :&, (1 << (di.instruction.args.first.sz || opsz)) - 1]
			end
			{ a[0] => e }
		when 'rdtsc'
			{ :eax => Expression::Unknown, :edx => Expression::Unknown }
		when /^(stos|movs)([bwd])$/
			e_op = $1
			sz = { 'b' => 1, 'w' => 2, 'd' => 4 }[$2]
			dir = :+
			dir = :- if di.block and (di.block.list.find { |ddi| ddi.opcode.name == 'std' } rescue nil)
			pesi = Indirection[:esi, sz, di.address]
			pedi = Indirection[:edi, sz, di.address]
			pfx = di.instruction.prefix || {}
			case e_op
			when 'movs'
				case pfx[:rep]
				when nil
					{ pedi => pesi, :esi => Expression[:esi, dir, sz], :edi => Expression[:edi, dir, sz] }
				else
					{ pedi => pesi, :esi => Expression::Unknown, :edi => Expression::Unknown }	# repz/repnz..
				end
			when 'stos'
				case pfx[:rep]
				when nil
					{ pedi => Expression[:eax], :edi => Expression[:edi, dir, sz] }
				else
					{ pedi => Expression[:eax], :edi => Expression[:edi, dir, [sz, :*, :ecx]] }	# XXX create an xref at edi+sz*ecx ?
				end
			end
		when 'clc'
			{ :eflag_c => Expression[0] }
		when 'stc'
			{ :eflag_c => Expression[1] }
		when 'cmc'
			{ :eflag_c => Expression[:'!', :eflag_c] }
		when 'cld'
			{ :eflag_d => Expression[0] }
		when 'std'
			{ :eflag_d => Expression[1] }
		when /^set(.*)/
			cd = decode_cc_to_expr($1)
			{ a[0] => Expression[cd] }
		when /^j(.*)/
			binding = { 'dummy_metasm_0' => Expression[a[0]] }
			if fl = decode_cc_to_expr($1)
				binding['dummy_metasm_1'] = fl	# mark eflags as read
			end
			binding
		when 'nop', 'pause', 'wait', 'cmp', 'test'
			{}
		else
			puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
			# assume nothing except the 1st arg
			case a[0]
			when Indirection, Symbol
				{ a[0] => Expression::Unknown }
			else
				{}
			end
		end
		# eflags side-effects
		sign = proc { |v| Expression[[[v, :&, mask], :>>, opsz-1], :'!=', 0] }
		case op
		when 'adc', 'add', 'and', 'cmp', 'or', 'sbb', 'sub', 'xor', 'test'
			e_op = { 'adc' => :+, 'add' => :+, 'and' => :&, 'cmp' => :-, 'or' => :|, 'sbb' => :-, 'sub' => :-, 'xor' => :^, 'test' => :& }[op]
			res = Expression[[a[0], :&, mask], e_op, [a[1], :&, mask]]
			res = Expression[res, e_op, :eflag_c] if op == 'adc' or op == 'sbb'

			binding[:eflag_z] = Expression[[res, :&, mask], :==, 0]
			binding[:eflag_s] = sign[res]
			binding[:eflag_c] = case e_op
				when :+
					Expression[res, :>, mask]
				when :-
					Expression[[a[0], :&, mask], :<, [a[1], :&, mask]]
				else
					Expression[0]
				end
			binding[:eflag_o] = case e_op
				when :+
					Expression[[sign[a[0]], :==, sign[a[1]]], :'&&', [sign[a[0]], :'!=', sign[res]]]
				when :-
					Expression[[sign[a[0]], :==, [:'!', sign[a[1]]]], :'&&', [sign[a[0]], :'!=', sign[res]]]
				else
					Expression[0]
				end
		when 'inc', 'dec', 'neg', 'shl', 'shr', 'sar', 'ror', 'rol', 'rcr', 'rcl', 'shld', 'shrd'
			res = binding[a[0]]
			binding[:eflag_z] = Expression[[res, :&, mask], :==, 0]
			binding[:eflag_s] = sign[res]
			case op
			when 'neg'
				binding[:eflag_c] = Expression[[res, :&, mask], :'!=', 0]
			when 'inc', 'dec'
				# don't touch carry flag
			else
				binding[:eflag_c] = Expression::Unknown
			end
			binding[:eflag_o] = case op
				when 'inc'
					Expression[[a[0], :&, mask], :==, mask >> 1]
				when 'dec'
					Expression[[res , :&, mask], :==, mask >> 1]
				when 'neg'
					Expression[[a[0], :&, mask], :==, (mask+1) >> 1]
				else
					Expression::Unknown	# TODO someday
				end
		when 'imul', 'mul', 'idiv', 'div'
			binding[:eflag_z] = binding[:eflag_s] = binding[:eflag_c] = binding[:eflag_o] = Expression::Unknown

		end
		binding
	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]

		case di.opcode.name
		when 'ret'
			return [Indirection[:esp, @size/8, di.address]]
		when 'jmp'
			a = di.instruction.args.first
			if a.kind_of? ModRM and a.imm and a.s == @size/8 and not a.b and s = dasm.get_section_at(Expression[a.imm, :-, 3*@size/8])
				# jmp table
				ret = [Expression[a.symbolic(di.address)]]
				v = -3
				loop do
					diff = Expression[s[0].decode_imm("u#@size".to_sym, @endianness), :-, di.address].reduce
					if diff.kind_of? ::Integer and diff.abs < 4096
						ret << Indirection[[a.imm, :+, v*@size/8], @size/8, di.address]
					elsif v > 0
						break
					end
					v += 1
				end
				return ret
			end
		end

		case tg = di.instruction.args.first
		when ModRM
			tg.sz ||= @size if tg.kind_of? ModRM
			[Expression[tg.symbolic(di.address)]]
		when Reg
			[Expression[tg.symbolic]]
		when Expression, ::Integer
			[Expression[tg]]
		else
			puts "unhandled setip at #{di.address} #{di.instruction}" if $DEBUG
			[]
		end
	end

	# checks if expr is a valid return expression matching the :saveip instruction
	def backtrace_is_function_return(expr, di=nil)
		expr = Expression[expr].reduce_rec
		expr.kind_of? Indirection and expr.len == @size/8 and expr.target == Expression[:esp]
	end

	# updates the function backtrace_binding
	# XXX assume retaddrlist is either a list of addr of ret or a list with a single entry which is an external function name (thunk)
	def backtrace_update_function_binding(dasm, faddr, f, retaddrlist)
		b = f.backtrace_binding

		# XXX handle retaddrlist for multiple/mixed thunks
		if retaddrlist and not dasm.decoded[retaddrlist.first] and di = dasm.decoded[faddr]
			# no return instruction, must be a thunk : find the last instruction (to backtrace from it)
			while ndi = dasm.decoded[di.block.to_subfuncret.to_a.first] || dasm.decoded[di.block.to_normal.to_a.first] and ndi.kind_of? DecodedInstruction
				di = ndi
			end
			if not di.block.to_subfuncret.to_a.first and di.block.to_normal and di.block.to_normal.length > 1
				thunklast = di.block.list.last.address
			end
		end
			
		bt_val = proc { |r|
			next if not retaddrlist
			bt = []
			retaddrlist.each { |retaddr|
				bt |= dasm.backtrace(Expression[r], (thunklast ? thunklast : retaddr),
					:include_start => true, :snapshot_addr => faddr, :origin => retaddr, :from_subfuncret => thunklast)
			}
			if bt.length != 1
				b[r] = Expression::Unknown
			else
				b[r] = bt.first
			end
		}
		[:eax, :ebx, :ecx, :edx, :esi, :edi, :ebp, :esp].each(&bt_val)

		return if f.need_finalize

		sz = @size/8
		if b[:ebp] != Expression[:ebp]
			# may be a custom 'enter' function (eg recent Visual Studio)
			# TODO put all memory writes in the binding ?
			[[:ebp], [:esp, :+, 1*sz], [:esp, :+, 2*sz], [:esp, :+, 3*sz]].each { |ptr|
				ind = Indirection[ptr, sz, faddr]
				bt_val[ind]
				b.delete(ind) if b[ind] and not [:ebx, :edx, :esi, :edi, :ebp].include? b[ind].reduce_rec
			}
		end
		if dasm.funcs_stdabi
			if b[:ebp] == Expression::Unknown
				puts "update_func_bind: #{Expression[faddr]} has ebp -> unknown, presume it is preserved" if $DEBUG
				b[:ebp] = Expression[:ebp]
			end
			if b[:esp] == Expression::Unknown and not f.btbind_callback
				puts "update_func_bind: #{Expression[faddr]} has esp -> unknown, use dynamic callback" if $DEBUG
				f.btbind_callback = disassembler_default_btbind_callback
			end
		else
			if b[:esp] != prevesp and not Expression[b[:esp], :-, :esp].reduce.kind_of?(::Integer)
				puts "update_func_bind: #{Expression[faddr]} has esp -> #{b[:esp]}" if $DEBUG
			end
		end

		# rename some functions
		# TODO database and real signatures
		rename =
		if Expression[b[:eax], :-, faddr].reduce == 0
			'geteip' # metasm pic linker
		elsif Expression[b[:eax], :-, :eax].reduce == 0 and Expression[b[:ebx], :-, Indirection[:esp, sz, nil]].reduce == 0
			'get_pc_thunk_ebx' # elf pic convention
		elsif Expression[b[:esp], :-, [:esp, :-, [Indirection[[:esp, :+, 2*sz], sz, nil], :+, 0x18]]].reduce == 0
			'__SEH_prolog'
		elsif Expression[b[:esp], :-, [:ebp, :+, sz]].reduce == 0 and Expression[b[:ebx], :-, Indirection[[:esp, :+, 4*sz], sz, nil]].reduce == 0
			'__SEH_epilog'
		end
		dasm.auto_label_at(faddr, rename, 'loc', 'sub') if rename

		b
	end

	# returns true if the expression is an address on the stack
	def backtrace_is_stack_address(expr)
		Expression[expr].expr_externals.include? :esp
	end

	# updates an instruction's argument replacing an expression with another (eg label renamed)
	def replace_instr_arg_immediate(i, old, new)
		i.args.map! { |a|
			case a
			when Expression
				a == old ? new : Expression[a.bind(old => new).reduce]
			when ModRM
				a.imm = (a.imm == old ? new : Expression[a.imm.bind(old => new).reduce]) if a.imm
				a
			else
				a
			end
		}
	end

	# returns a DecodedFunction from a parsed C function prototype
	# TODO rebacktrace already decoded functions (load a header file after dasm finished)
	# TODO walk structs args
	def decode_c_function_prototype(cp, sym, orig=nil)
		sym = cp.toplevel.symbol[sym] if sym.kind_of?(::String)
		df = DecodedFunction.new
		orig ||= Expression[sym.name]

		new_bt = proc { |expr, rlen|
			df.backtracked_for << BacktraceTrace.new(expr, orig, expr, rlen ? :r : :x, rlen)
		}

		# return instr emulation
		new_bt[Indirection[:esp, @size/8, orig], nil] if not sym.attributes.to_a.include? 'noreturn'

		# register dirty (XXX assume standard ABI)
		df.backtrace_binding.update :eax => Expression::Unknown, :ecx => Expression::Unknown, :edx => Expression::Unknown

		# emulate ret <n>
		al = cp.typesize[:ptr]
		if sym.attributes.to_a.include? 'stdcall'
			argsz = sym.type.args.inject(al) { |sum, a| sum += (cp.sizeof(a) + al - 1) / al * al }
			df.backtrace_binding[:esp] = Expression[:esp, :+, argsz]
		else
			df.backtrace_binding[:esp] = Expression[:esp, :+, al]
		end

		# scan args for function pointers
		# TODO walk structs/unions..
		stackoff = al
		sym.type.args.to_a.each { |a|
			if a.type.untypedef.kind_of? C::Pointer
				pt = a.type.untypedef.type.untypedef
				if pt.kind_of? C::Function
					new_bt[Indirection[[:esp, :+, stackoff], al, orig], nil]
					df.backtracked_for.last.detached = true
				elsif pt.kind_of? C::Struct
					new_bt[Indirection[[:esp, :+, stackoff], al, orig], al]
				else
					new_bt[Indirection[[:esp, :+, stackoff], al, orig], cp.sizeof(nil, pt)]
				end
			end
			stackoff += (cp.sizeof(a) + al - 1) / al * al
		}

		df
	end

	# the proc for the :default backtrace_binding callback of the disassembler
	# tries to determine the stack offset of unprototyped functions
	# working:
	#   checks that origin is a ret, that expr is an indirection from :esp and that expr.origin is the ret
	#   bt_walk from calladdr until we finds a call into us, and assumes it is the current function start
	#   TODO handle foo: call bar ; bar: pop eax ; call <withourcallback> ; ret -> bar is not the function start (foo is)
	#   then backtrace expr from calladdr to funcstart (snapshot), using esp -> esp+<stackoffvariable>
	#   from the result, compute stackoffvariable (only if trivial)
	# will not work if the current function calls any other unknown function (unless all are __cdecl)
	# will not work if the current function is framed (ebp leave ret): in this case the function will return, but its :esp will be unknown
	# TODO remember failed attempts and rebacktrace them if we find our stackoffset later ? (other funcs may depend on us)
	# if the stack offset is found and funcaddr is a string, fixup the static binding and remove the dynamic binding
	# TODO dynamise thunks
	def disassembler_default_btbind_callback
		proc { |dasm, bind, funcaddr, calladdr, expr, origin, maxdepth|
			@dasm_func_default_off ||= {}
			if off = @dasm_func_default_off[[dasm, calladdr]]
				bind = bind.merge(:esp => Expression[:esp, :+, off])
				break bind
			end
			break bind if not odi = dasm.decoded[origin] or odi.opcode.name != 'ret'
			expr = expr.reduce_rec if expr.kind_of? Expression
			break bind unless expr.kind_of? Indirection and expr.origin == origin
			break bind unless expr.externals.reject { |e| e =~ /^autostackoffset_/ } == [:esp]

			# scan from calladdr for the probable parent function start
			func_start = nil
			dasm.backtrace_walk(true, calladdr, false, false, nil, maxdepth) { |ev, foo, h|
				if ev == :up and h[:sfret] != :subfuncret and di = dasm.decoded[h[:to]] and di.opcode.name == 'call'
					func_start = h[:from]
					break
				elsif ev == :end
					# entrypoints are functions too
					func_start = h[:addr]
					break
				end
			}
			break bind if not func_start
			puts "automagic #{funcaddr}: found func start for #{dasm.decoded[origin]} at #{Expression[func_start]}" if dasm.debug_backtrace
			s_off = "autostackoffset_#{Expression[funcaddr]}_#{Expression[calladdr]}"
			list = dasm.backtrace(expr.bind(:esp => Expression[:esp, :+, s_off]), calladdr, :include_start => true, :snapshot_addr => func_start, :maxdepth => maxdepth, :origin => origin)
			e_expr = list.find { |e_expr|
				# TODO cleanup this
				e_expr = Expression[e_expr].reduce_rec
				next if not e_expr.kind_of? Indirection
				off = Expression[[:esp, :+, s_off], :-, e_expr.target].reduce
				off.kind_of? Integer and off >= @size/8 and off < 10*@size/8 and (off % (@size/8)) == 0
			} || list.first

			e_expr = e_expr.rexpr if e_expr.kind_of? Expression and e_expr.op == :+ and not e_expr.lexpr
			break bind unless e_expr.kind_of? Indirection

			off = Expression[[:esp, :+, s_off], :-, e_expr.target].reduce
			case off
			when Expression
                                bd = off.externals.grep(/^stackoff=/).inject({}) { |bd, xt| bd.update xt => @size/8 }
                                bd.delete s_off
                                # all __cdecl
                                off = @size/8 if off.bind(bd).reduce == @size/8
			when Integer
				if off < @size/8 or off > 20*@size/8 or (off % (@size/8)) != 0
					puts "autostackoffset: ignoring off #{off} for #{Expression[funcaddr]} from #{dasm.decoded[calladdr]}" if $VERBOSE
					off = :unknown 
				end
                        end

                        bind = bind.merge :esp => Expression[:esp, :+, off] if off != :unknown
                        if funcaddr != :default
                                if not off.kind_of? ::Integer
                                        #XXX we allow the current function to return, so we should handle the func backtracking its :esp
                                        #(and other register that are saved and restored in epilog)
                                        puts "stackoff #{dasm.decoded[calladdr]} | #{Expression[func_start]} | #{expr} | #{e_expr} | #{off}" if dasm.debug_backtrace
                                else
                                        puts "autostackoffset: found #{off} for #{Expression[funcaddr]} from #{dasm.decoded[calladdr]}" if $VERBOSE
                                        dasm.function[funcaddr].btbind_callback = nil
                                        dasm.function[funcaddr].backtrace_binding = bind

					# rebacktrace the return address, so that other unknown funcs that depend on us are solved
					dasm.backtrace(Indirection[:esp, @size/8, origin], origin, :origin => origin)
                                end
                        else
				if off.kind_of? ::Integer and dasm.decoded[calladdr]
                                        puts "autostackoffset: found #{off-@size/8} for #{dasm.decoded[calladdr]}" if $VERBOSE
					di = dasm.decoded[calladdr]
					di.comment.delete_if { |c| c =~ /^stackoff=/ } if di.comment
					di.add_comment "stackoff=#{off-@size/8}"
					@dasm_func_default_off[[dasm, calladdr]] = off

					dasm.backtrace(Indirection[:esp, @size/8, origin], origin, :origin => origin)
				elsif cachedoff = @dasm_func_default_off[[dasm, calladdr]]
					bind[:esp] = Expression[:esp, :+, cachedoff]
				else
					dasm.decoded[calladdr].add_comment "stackoff=#{off-@size/8}"
				end

                                puts "stackoff #{dasm.decoded[calladdr]} | #{Expression[func_start]} | #{expr} | #{e_expr} | #{off}" if dasm.debug_backtrace
                        end

                        bind
                }
        end

	# the :default backtracked_for callback
	# returns empty unless funcaddr is not default or calladdr is a call or a jmp
        def disassembler_default_btfor_callback
                proc { |dasm, btfor, funcaddr, calladdr|
                        if funcaddr != :default
                                btfor
                        elsif di = dasm.decoded[calladdr] and (di.opcode.name == 'call' or di.opcode.name == 'jmp')
                                btfor
                        else
				[]
                        end
                }
        end

	# returns a DecodedFunction suitable for :default
	# uses disassembler_default_bt{for/bind}_callback
	def disassembler_default_func
		cp = new_cparser
		cp.parse 'void stdfunc(void);'
		f = decode_c_function_prototype(cp, 'stdfunc', :default)
		f.backtrace_binding[:esp] = Expression[:esp, :+, :unknown]
		f.btbind_callback = disassembler_default_btbind_callback
		f.btfor_callback  = disassembler_default_btfor_callback
		f
	end
end
end
