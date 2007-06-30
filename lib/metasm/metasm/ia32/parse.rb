#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/opcodes'
require 'metasm/ia32/encode'
require 'metasm/parse'

module Metasm
class Ia32
class ModRM
	# may return a SegReg
	# must be called before SegReg parser (which could match only the seg part of a modrm)
	def self.parse(lexer, otok)
		tok = otok
		
		# read operand size specifier
		if tok and tok.type == :string and tok.raw =~ /^(?:byte|[dqo]?word|_(\d+)bits)$/
			ptsz = 
			if $1
				$1.to_i
			else
				case tok.raw
				when  'byte':   8
				when  'word':  16
				when 'dword':  32
				when 'qword':  64
				when 'oword': 128
				else raise otok, 'mrm: bad ptr size'
				end
			end
			lexer.skip_space
			if tok = lexer.readtok and tok.type == :string and tok.raw == 'ptr'
				lexer.skip_space
				tok = lexer.readtok
			end
		end

		# read segment selector
		if tok and tok.type == :string and seg = SegReg.s_to_i[tok.raw]
			lexer.skip_space
			seg = SegReg.new(seg)
			if not ntok = lexer.readtok or ntok.type != :punct or ntok.raw != ':'
				raise otok, 'invalid modrm' if ptsz
				lexer.unreadtok ntok
				return seg
			end
			lexer.skip_space
			tok = lexer.readtok
		end

		# ensure we have a modrm
		if not tok or tok.type != :punct or tok.raw != '['
			raise otok, 'invalid modrm' if ptsz or seg
			return
		end
		lexer.skip_space_eol

		# support fasm syntax [fs:eax] for segment selector
		if tok = lexer.readtok and tok.type == :string and not seg and seg = SegReg.s_to_i[tok.raw]
			raise otok, 'invalid modrm' if not ntok = lexer.readtok or ntok.type != :punct or ntok.raw != ':'
			seg = SegReg.new(seg)
			lexer.skip_space_eol
		else
			lexer.unreadtok tok
		end

		# read modrm content as generic expression
		content = Expression.parse(lexer)
		lexer.skip_space_eol
		raise(otok, 'bad modrm') if not content or not ntok = lexer.readtok or ntok.type != :punct or ntok.raw != ']'

		# converts matching externals to Regs in an expression
		regify = proc { |o|
			case o
			when Expression
				o.lexpr = regify[o.lexpr]
				o.rexpr = regify[o.rexpr]
				o
			when String
				if Reg.s_to_i.has_key? o
					Reg.new(*Reg.s_to_i[o])
				else o
				end
			else o
			end
		}

		s = i = b = imm = nil

		# assigns the Regs in the expression to base or index field of the modrm
		walker = proc { |o|
			case o
			when nil
			when Reg
				if b
					raise otok, 'mrm: too many regs' if i
					i = o
					s = 1
				else
					b = o
				end
			when Expression
				if o.op == :* and (o.rexpr.kind_of? Reg or o.lexpr.kind_of? Reg)
					# scaled index
					raise otok, 'mrm: too many indexes' if i
					s = o.lexpr
					i = o.rexpr
					s, i = i, s if s.kind_of? Reg
					raise otok, 'mrm: bad scale' unless s.kind_of? Integer
				elsif o.op == :+
					# recurse
					walker[o.lexpr]
					walker[o.rexpr]
				else
					# found (a part of) the immediate
					imm = Expression[imm, :+, o]
				end
			else
				# found (a part of) the immediate
				imm = Expression[imm, :+, o]
			end
		}

		# do it
		walker[regify[content.reduce]]

		# ensure found immediate is really an immediate
		raise otok, 'mrm: reg in imm' if imm.kind_of? Expression and not imm.externals.grep(Reg).empty?

		# find default address size
		adsz = b ? b.sz : i ? i.sz : lexer.program.cpu.size
		# ptsz may be nil now, will be fixed up later (in parse_instr_fixup) to match another instruction argument's size
		new adsz, ptsz, s, i, b, imm, seg
	end
end


	# handles cpu-specific parser instruction, falls back to Ancestor's version if unknown keyword
	# XXX changing the cpu size in the middle of the code may have baaad effects...
	def parse_parser_instruction(lexer, instr)
		case instr.raw.downcase
		when '.mode', '.bits'
			lexer.skip_space
			if tok = lexer.readtok and tok.type == :string and (tok.raw == '16' or tok.raw == '32')
				@size = tok.raw.to_i
				lexer.skip_space
				raise instr, 'syntax error' if ntok = lexer.nexttok and ntok.type != :eol
			else
				raise instr, 'invalid cpu mode'
			end
		else super
		end
	end

	def parse_prefix(i, pfx)
		# XXX check for redefinition ?
		# implicit 'true' return value when assignment occur
		case pfx
		when 'lock': i.prefix[:lock] = true
		when 'rep':            i.prefix[:rep] = 'rep'
		when 'repe', 'repz':   i.prefix[:rep] = 'repz'
		when 'repne', 'repnz': i.prefix[:rep] = 'repnz'
		end
	end

	# parses a arbitrary ia32 instruction argument
	def parse_argument(lexer)
		# reserved names (registers/segments etc)
		@args_token ||= (Argument.double_list + Argument.simple_list).map { |a| a.s_to_i.keys }.flatten.inject({}) { |h, e| h.update e => true }
		 
		lexer.skip_space
		return if not tok = lexer.readtok

		if tok.type == :string and tok.raw == 'ST'
			lexer.skip_space
			if ntok = lexer.readtok and ntok.type == :punct and ntok.raw == '('
				lexer.skip_space
				if not nntok = lexer.readtok or nntok.type != :string or nntok.raw != /^[0-9]$/ or
						not ntok = (lexer.skip_space; lexer.readtok) or ntok.type != :punct or ntok.raw != ')'
					raise tok, 'invalid FP register'
				else
					tok.raw << '(' << nntok.raw << ')'
					if FpReg.s_to_i.has_key? tok.raw
						return FpReg.new(FpReg.s_to_i[tok.raw])
					else
						raise tok, 'invalid FP register'
					end
				end
			else
				lexer.unreadtok ntok
			end
		end

		if ret = ModRM.parse(lexer, tok)
			ret
		elsif @args_token[tok.raw]
			# most frequent first: standard register
			Argument.double_list.each { |a|
				return a.new(*a.s_to_i[tok.raw]) if a.s_to_i.has_key? tok.raw
			}
			Argument.simple_list.each { |a|
				return a.new( a.s_to_i[tok.raw]) if a.s_to_i.has_key? tok.raw
			}
			raise tok, 'internal error'
		else
			lexer.unreadtok tok
			expr = Expression.parse(lexer)
			lexer.skip_space

			# may be a farptr
			if expr and ntok = lexer.readtok and ntok.type == :punct and ntok.raw == ':'
				raise tok, 'invalid farptr' if not addr = Expression.parse(lexer)
				Farptr.new expr, addr
			else
				lexer.unreadtok ntok
				expr
			end
		end
	end

	# check if the argument matches the opcode's argument spec
	def parse_arg_valid?(o, spec, arg)
		case spec
		when :reg
			arg.class == Reg and
				if not o.fields[:w] or o.name == 'movsx' or o.name == 'movzx'
					# we know the prototype of movsx: :reg is the large param
					# no al/bl/bh/etc allowed
					arg.sz >= 16
				else true
				end
		when :modrm
			(arg.class == ModRM   or arg.class == Reg) and
				if not o.fields[:w]
					!arg.sz or arg.sz >= 16
				elsif o.name == 'movsx' or o.name == 'movzx'
					# we know the prototype of movsx: :modrm is the small param
					!arg.sz or arg.sz <= 16
				else true
				end
		when :i:        arg.kind_of? Expression
		when :imm_val1: arg.kind_of? Expression and arg.reduce == 1
		when :imm_val3: arg.kind_of? Expression and arg.reduce == 3
		when :reg_eax:  arg.class == Reg     and arg.val == 0
		when :reg_cl:   arg.class == Reg     and arg.val == 1 and arg.sz == 8
		when :reg_dx:   arg.class == Reg     and arg.val == 2 and arg.sz == 16
		when :seg3:     arg.class == SegReg
		when :seg2:     arg.class == SegReg  and arg.val < 4
		when :seg2A:    arg.class == SegReg  and arg.val < 4 and arg.val != 1
		when :eeec:     arg.class == CtrlReg
		when :eeed:     arg.class == DbgReg
		when :modrmA:   arg.class == ModRM
		when :mrm_imm:  arg.class == ModRM   and not arg.s and not arg.i and not arg.b
		when :farptr:   arg.class == Farptr
		when :regfp:    arg.class == FpReg
		when :regfp0:   arg.class == FpReg   and (arg.val == nil or arg.val == 0)	# XXX optional argument
		when :modrmmmx: arg.class == ModRM   or (arg.class == SimdReg and arg.sz == 64)
		when :regmmx:   arg.class == SimdReg and arg.sz == 64
		when :modrmxmm: arg.class == ModRM   or (arg.class == SimdReg and arg.sz == 128)
		when :regxmm:   arg.class == SimdReg and arg.sz == 128
		when :i8, :u8, :u16:
			Expression.in_range?(arg, spec) != false	# true or nil allowed
		else raise EncodeError, "Internal error: unknown argument specification #{spec.inspect}"
		end
	end

	# fixup the ptsz of a modrm argument, defaults to other argument size or current cpu mode
	def parse_instruction_fixup(i)
		if m = i.args.grep(ModRM).first and not m.sz
			if i.opname == 'movzx' or i.opname == 'movsx'
				m.sz = 8
			else
				if r = i.args.grep(Reg).first
					m.sz = r.sz
				else
					# this is also the size of ctrlreg/dbgreg etc
					# XXX fpu/simd ?
					m.sz = @size
				end
			end
		end
	end
end
end
