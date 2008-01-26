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
		(instr.prefix[:list] ||= []) << byte

		case byte
		when 0x66: instr.prefix[:opsz] = true
		when 0x67: instr.prefix[:adsz] = true
		when 0xF0: instr.prefix[:lock] = true
		when 0xF2: instr.prefix[:rep]  = :nz
		when 0xF3: instr.prefix[:rep]  = :z	# postprocessed by decode_instr
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
				  (fld = op.fields[:modrmA] and (bseq[fld[0]] >> fld[1]) & 0xC0 == 0xC0) or
				  (sz  = op.props[:opsz]    and ((di.instruction.prefix[:opsz] and @size != 48-sz) or
					(not di.instruction.prefix[:opsz] and @size != sz))) or
				  (pfx = op.props[:needpfx] and not (di.instruction.prefix[:list] || []).include? pfx)
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

		field_val = proc { |f|
			if fld = op.fields[f]
				(bseq[fld[0]] >> fld[1]) & @fields_mask[f]
			end
		}

		if field_val[:w] == 0
			opsz = 8
		elsif di.instruction.prefix[:opsz]
			opsz = 48 - @size
		else
			opsz = @size
		end

		if di.instruction.prefix[:adsz]
			adsz = 48 - @size
		else
			adsz = @size
		end
		
		op.args.each { |a|
			mmxsz = ((op.props[:xmmx] && di.instruction.prefix[:opsz]) ? 128 : 64)
			di.instruction.args << case a
			when :reg:    Reg.new     field_val[a], opsz
			when :eeec:   CtrlReg.new field_val[a]
			when :eeed:   DbgReg.new  field_val[a]
			when :seg2, :seg2A, :seg3, :seg3A: SegReg.new field_val[a]
			when :regfp:  FpReg.new   field_val[a]
			when :regmmx: SimdReg.new field_val[a], mmxsz
			when :regxmm: SimdReg.new field_val[a], 128

			when :farptr: Farptr.decode edata, @endianness, adsz
			when :i8, :u8, :u16: Expression[edata.decode_imm(a, @endianness)]
			when :i: Expression[edata.decode_imm("#{op.props[:unsigned_imm] ? 'a' : 'i'}#{opsz}".to_sym, @endianness)]

			when :mrm_imm:  ModRM.decode edata, (adsz == 16 ? 6 : 5), @endianness, adsz, opsz, di.instruction.prefix[:seg]
			when :modrm, :modrmA: ModRM.decode edata, field_val[a], @endianness, adsz, (op.props[:argsz] || opsz), di.instruction.prefix[:seg]
			when :modrmmmx: ModRM.decode edata, field_val[:modrm], @endianness, adsz, mmxsz, di.instruction.prefix[:seg], SimdReg
			when :modrmxmm: ModRM.decode edata, field_val[:modrm], @endianness, adsz, 128, di.instruction.prefix[:seg], SimdReg

			when :imm_val1: Expression[1]
			when :imm_val3: Expression[3]
			when :reg_cl:   Reg.new 1, 8
			when :reg_eax:  Reg.new 0, opsz
			when :reg_dx:   Reg.new 2, 16
			when :regfp0:   FpReg.new nil	# implicit?
			else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
			end
		}

		di.bin_length += edata.ptr - before_ptr

		if op.name == 'movsx' or op.name == 'movzx'
			if opsz == 8
				di.instruction.args[1].sz = 8
			else
				di.instruction.args[1].sz = 16
			end
			if di.instruction.prefix[:opsz]
				di.instruction.args[0].sz = 48 - @size
			else
				di.instruction.args[0].sz = @size
			end
		end

		di.instruction.prefix.delete :opsz
		di.instruction.prefix.delete :adsz
		di.instruction.prefix.delete :seg
		case r = di.instruction.prefix.delete(:rep)
		when :nz
			if di.opcode.props[:strop]
				di.instruction.prefix[:rep] = 'rep'
			elsif di.opcode.props[:stropz]
				di.instruction.prefix[:rep] = 'repnz'
			end
		when :z
			if di.opcode.props[:stropz]
				di.instruction.prefix[:rep] = 'repz'
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

	def backtrace_binding(di)
		a = di.instruction.args.map { |arg|
			case arg
			when ModRM: arg.symbolic(di.address)
			when Reg, SimdReg: arg.symbolic
			else arg
			end
		}

		mask = (1 << @size)-1	# 0xffff_ffff for 32bits
		case op = di.opcode.name
		when 'mov', 'movsx', 'movzx', 'movd', 'movq': { a[0] => Expression[a[1]] }
		when 'lea': { a[0] => a[1].target }
		when 'xchg': { a[0] => Expression[a[1]], a[1] => Expression[a[0]] }
		when 'add', 'sub', 'or', 'xor', 'and', 'pxor'
			op = { 'add' => :+, 'sub' => :-, 'or' => :|, 'and' => :&, 'xor' => :^, 'pxor' => :^ }[op]
			ret = Expression[a[0], op, a[1]]
			# optimises :eax ^ :eax => 0
			# avoid hiding memory accesses (to not hide possible fault)
			ret = Expression[ret.reduce] if not a[0].kind_of? Indirection
			{ a[0] => ret }
		when 'inc': { a[0] => Expression[a[0], :+, 1] }
		when 'dec': { a[0] => Expression[a[0], :-, 1] }
		when 'not': { a[0] => Expression[a[0], :^, mask] }
		when 'neg': { a[0] => Expression[:-, a[0]] }
		when 'rol', 'ror', 'rcl', 'rcr':
			invop = (op[-1] == ?r ? :<< : :>>)
			op = (op[-1] == ?r ? :>> : :<<)
			# ror a, b  =>  (a >> b) | (a << (32-b))
			{ a[0] => Expression[[[a[0], op, [a[1], :%, @size]], :|, [a[0], invop, [[@size, :-, a[1]], :%, @size]]], :&, mask] }
		when 'sar', 'shl', 'sal': { a[0] => Expression[a[0], (op[-1] == ?r ? :>> : :<<), [a[1], :%, @size]] }
		when 'shr': { a[0] => Expression[[a[0], :&, mask], :>>, [a[1], :%, @size]] }
		when 'cdq': { :edx => Expression[0xffff_ffff, :*, [[:eax, :>>, @size-1], :&, 1]] }
		when 'push'
			{ :esp => Expression[:esp, :-, @size/8],
			  Indirection.new(Expression[:esp], @size/8, di.address) => Expression[a[0]] }
		when 'pop'
			{ :esp => Expression[:esp, :+, @size/8],
			  a[0] => Indirection.new(Expression[:esp], @size/8, di.address) }
		when 'pushfd': { :esp => Expression[:esp, :-, @size/8], Indirection.new(Expression[:esp], @size/8, di.address) => Expression::Unknown }
		when 'popfd':  { :esp => Expression[:esp, :+, @size/8] }
		when 'pushad'
			ret = {}
			st_off = 0
			[:eax, :ecx, :edx, :ebx, :esp, :ebp, :esi, :edi].reverse_each { |r|
				ret[Indirection.new(Expression[:esp, :+, st_off].reduce, @size/8, di.address)] = Expression[r]
				st_off += @size/8
			}
			ret[:esp] = Expression[:esp, :-, st_off]
			ret
		when 'popad'
			ret = {}
			st_off = 0
			[:eax, :ecx, :edx, :ebx, :esp, :ebp, :esi, :edi].reverse_each { |r|
				ret[r] = Indirection.new(Expression[:esp, :+, st_off].reduce, @size/8, di.address)
				st_off += @size/8
			}
			ret
		when 'call'
			eoff = Expression[di.block.address, :+, di.block_offset + di.bin_length]
			{ :esp => Expression[:esp, :-, @size/8],
			  Indirection.new(Expression[:esp], @size/8, di.address) => Expression[eoff.reduce] }
		when 'ret': { :esp => Expression[:esp, :+, [@size/8, :+, a[0] || 0]] }
		when 'loop': { :ecx => Expression[:ecx, :-, 1] }
		when 'enter'
			depth = a[1].reduce % 32
			b = { Indirection.new(Expression[:esp], @size/8, di.address) => Expression[:ebp], :ebp => Expression[:esp, :-, @size/8],
					:esp => Expression[:esp, :-, a[0].reduce + ((@size/8) * depth)] }
			(1..depth).each { |i| # XXX test me !
				b[Indirection.new(Expression[:esp, :-, i*@size/8], @size/8, di.address)] = Indirection.new(Expression[:ebp, :-, i*@size/8], @size/8, di.address) }
			b
		when 'leave': { :ebp => Indirection.new(Expression[:ebp], @size/8, di.address), :esp => Expression[:ebp, :+, @size/8] }
		when 'aaa': { :eax => Expression::Unknown }
		when 'imul'
			if a[2]: e = Expression[a[1], :*, a[2]]
			else e = Expression[[a[0], :*, a[1]], :&, (1 << (di.instruction.args.first.sz || @size)) - 1]
			end
			{ a[0] => e }
		when 'rdtsc': { :eax => Expression::Unknown, :edx => Expression::Unknown }
		when /^(stos|movs)([bwd])$/
			op = $1
			sz = { 'b' => 1, 'w' => 2, 'd' => 4 }[$2]
			dir = :+
			dir = :- if di.block.list.find { |ddi| ddi.opcode.name == 'std' } rescue nil
			pesi = Indirection.new(Expression[:esi], sz, di.address)
			pedi = Indirection.new(Expression[:edi], sz, di.address)
			case op
			when 'movs'
				case di.instruction.prefix[:rep]
				when nil: { pedi => pesi, :esi => Expression[:esi, dir, sz], :edi => Expression[:edi, dir, sz] }
				else      { pedi => pesi, :esi => Expression::Unknown, :edi => Expression::Unknown }	# repz/repnz..
				end
			when 'stos'
				case di.instruction.prefix[:rep]
				when nil: { pedi => Expression[:eax], :edi => Expression[:edi, dir, sz] }
				else      { pedi => Expression[:eax], :edi => Expression[:edi, dir, [sz, :*, :ecx]] }	# XXX create an xref at edi+sz*ecx ?
				end
			end
		else
			if %[nop cmp test jmp jz jnz js jns jo jno jg jge jb jbe ja jae jl jle jnb jnbe jp jnp jnl jnle].include? op	# etc etc
				# XXX eflags !
				b = a.inject({}) { |b, foo| b.update "dummy#{b.length}".to_sym => foo } # mark args as read (modrm)
			else
				puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
				# assume nothing except the arg list is modified
				(a.grep(Indirection) + a.grep(::Symbol)).inject({}) { |h, s| h.update s => Expression::Unknown }
			end
		end

	end

	def get_xrefs_x(dasm, di)
		return [] if not di.opcode.props[:setip]

		return [Indirection.new(Expression[:esp], @size/8, di.address)] if di.opcode.name == 'ret'

		if di.opcode.name == 'jmp'
			a = di.instruction.args.first
			if a.kind_of? ModRM and a.imm and a.s == @size/8 and not a.b and s = dasm.get_section_at(Expression[a.imm, :-, 3*@size/8])
				# jmp table
				ret = [Expression[a.symbolic(di.address)]]
				v = -3
				loop do
					diff = Expression[s[0].decode_imm("u#@size".to_sym, @endianness), :-, di.address].reduce
					if diff.kind_of? ::Integer and diff.abs < 4096
						ret << Indirection.new(Expression[a.imm, :+, v*@size/8], @size/8, di.address)
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
		when Farptr
			puts "far pointer unhandled at #{di.address} #{di.instruction}" if $VERBOSE
			[]
		else raise "internal error: ia32 bad setip arg in #{di.instruction} #{tg.inspect}"
		end
	end

	# checks if expr is a valid return expression matching the :saveip instruction
	def backtrace_is_function_return(expr, di=nil)
		expr = expr.reduce
		expr = expr.rexpr if expr.kind_of? Expression and not expr.lexpr and expr.op == :+
		expr.kind_of? Indirection and expr.len == @size/8 and expr.target == Expression[:esp]
	end

	# updates the function backtrace_binding
	def backtrace_update_function_binding(dasm, faddr, f, retaddr)
		b = f.backtrace_binding
		prevesp = b[:esp]
		bt_val = proc { |r|
			next if b[r] == Expression::Unknown
			bt = dasm.backtrace(Expression[r], retaddr, :include_start => true, :snapshot_addr => faddr, :origin => retaddr)
			if bt.length != 1 or (b[r] and bt.first != b[r])
				b[r] = Expression::Unknown
			else
				b[r] = bt.first
			end
		}
		[:eax, :ebx, :ecx, :edx, :esi, :edi, :ebp, :esp].each(&bt_val)
		b[:esp] = prevesp if prevesp and b[:esp] == Expression::Unknown

		puts "update_func_bind: #{Expression[faddr]} has esp -> #{b[:esp]}" if b[:esp] != prevesp and not Expression[b[:esp], :-, :esp].reduce.kind_of?(::Integer) if $VERBOSE
		if b[:ebp] != Expression[:ebp]
			# may be a custom 'enter' function (eg recent Visual Studio)
			bt_val[Indirection.new(Expression[:ebp], @size/8, faddr)]
		end

		# rename some functions
		case b[:eax].reduce
		when faddr # metasm pic linker
			dasm.label_at(faddr, 'geteip', 'loc', 'sub')
		when Expression[:eax] # check elf pic convention
			dasm.label_at(faddr, 'get_pc_thunk_ebx', 'loc', 'sub') if b[:ebx].reduce == Expression[Indirection.new(Expression[:esp], @size/8, nil)]
		end
	end

	# returns true if the expression is an address on the stack
	def backtrace_is_stack_address(expr)
		Expression[expr].externals.include? :esp
	end

	# updates an instruction's argument replacing an expression with another (eg label renamed)
	def replace_instr_arg_immediate(i, old, new)
		i.args.map! { |a|
			case a
			when Expression: a == old ? new : Expression[a.bind(old => new).reduce]
			when ModRM
				a.imm = (a.imm == old ? new : Expression[a.imm.bind(old => new).reduce]) if a.imm
				a
			else a
			end
		}
	end

	# returns a DecodedFunction from a parsed C function prototype
	# TODO walk structs args
	def decode_c_function_prototype(cp, sym, orig=nil)
		sym = cp.toplevel.symbol[sym] if sym.kind_of?(::String)
		df = DecodedFunction.new
		orig ||= Expression[sym.name]

		new_bt = proc { |expr, rlen|
			df.backtracked_for << BacktraceTrace.new(expr, orig, rlen ? :r : :x, rlen)
		}

		# return instr emulation
		new_bt[Indirection.new(Expression[:esp], @size/8, orig), nil] if not sym.attributes.to_a.include? 'noreturn'

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
					new_bt[Indirection.new(Expression[:esp, :+, stackoff], al, orig), nil]
					df.backtracked_for.last.detached = true
				elsif pt.kind_of? C::Struct
					new_bt[Indirection.new(Expression[:esp, :+, stackoff], al, orig), al]
				else
					new_bt[Indirection.new(Expression[:esp, :+, stackoff], al, orig), cp.sizeof(nil, pt)]
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
aoeu = true
			end
			next bind if not odi = dasm.decoded[origin] or odi.opcode.name != 'ret'
			expr = expr.reduce
			expr = expr.rexpr if expr.kind_of? Expression and expr.op == :+ and not expr.lexpr
			next bind unless expr.kind_of? Indirection and expr.origin == origin
			ptr = expr.target
			reg = ptr.externals.reject { |e| e =~ /^autostackoffset_/ }
			next bind unless reg == [:esp]

			# scan from calladdr for the probable parent function start
			func_start = nil
			dasm.backtrace_walk(true, calladdr, false, false, nil, maxdepth) { |ev, foo, h|
				if ev == :up and not h[:sfret] and di = dasm.decoded[h[:to]] and di.opcode.name == 'call'
					# check that that call has not func_start as subfunction
					otherfunc = false
					di.block.each_subfunction { |sf| otherfunc = true if dasm.normalize(sf) == h[:from] }
					next false if otherfunc
					
					func_start = h[:from]
					break
				elsif ev == :end
					# assume entrypoints are functions too
					func_start = h[:addr]
					break
				end
			}
			next bind if not func_start
			puts "automagic #{funcaddr}: found func start for #{dasm.decoded[origin]} at #{Expression[func_start]}" if $DEBUG
			s_off = "autostackoffset_#{Expression[funcaddr]}_#{Expression[calladdr]}"
			list = dasm.backtrace(expr.bind(:esp => Expression[:esp, :+, s_off]), calladdr, :include_start => true, :snapshot_addr => func_start, :maxdepth => maxdepth, :origin => origin)
			next bind if list.length != 1
			e_expr = list.first
			e_expr = e_expr.rexpr if e_expr.kind_of? Expression and e_expr.op == :+ and not e_expr.lexpr
			next bind unless e_expr.kind_of? Indirection

			off = Expression[[:esp, :+, s_off], :-, e_expr.target].reduce
			case off
			when Expression
                                bd = off.externals.grep(/^autostackoffset_/).inject({}) { |bd, xt| bd.update xt => @size/8 }
                                bd.delete s_off
                                # all __cdecl
                                off = @size/8 if off.bind(bd).reduce == @size/8
			when Integer
				if off < @size/8 or off > 10*@size/8 or (off % (@size/8)) != 0
					puts "autostackoffset: ignoring off #{off} for #{Expression[funcaddr]} from #{dasm.decoded[calladdr]}" if $VERBOSE
					off = :unknown 
				end
                        end

                        bind = bind.merge :esp => Expression[:esp, :+, off] if off != :unknown
                        if funcaddr != :default
                                if not off.kind_of? ::Integer
                                        #register origin and rebacktrace it if we ever find our stackoff (to solve other unknown that depend on us)
                                        #XXX we allow the current function to return, so we should handle the func backtracking its :esp
                                        #(and other register that are saved and restored in epilog)
                                        puts "stackoff #{dasm.decoded[origin]} | #{Expression[func_start]} | #{expr} | #{e_expr} | #{off}" if $DEBUG
                                else
                                        puts "autostackoffset: found #{off} for #{Expression[funcaddr]} from #{dasm.decoded[calladdr]}" if $VERBOSE
                                        dasm.function[funcaddr].btbind_callback = nil
                                        dasm.function[funcaddr].backtrace_binding = bind
                                        #rebacktrace registered origins
                                end
                        else
				if off.kind_of? ::Integer and dasm.decoded[calladdr]
                                        puts "autostackoffset: using #{off} for #{dasm.decoded[calladdr]}" if $VERBOSE
					dasm.decoded[calladdr].add_comment "autostackoffset #{off}"
					@dasm_func_default_off[[dasm, calladdr]] = off
				elsif cachedoff = @dasm_func_default_off[[dasm, calladdr]]
					bind[:esp] = Expression[:esp, :+, cachedoff]
				else
					dasm.decoded[calladdr].add_comment "autostackoffset #{off}"
				end
                                # cache calladdr/funcaddr/origin -> off for current function binding ?
                                puts "stackoff #{dasm.decoded[origin]} | #{Expression[func_start]} | #{expr} | #{e_expr} | #{off}" if $DEBUG
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
