#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/opcodes'
require 'metasm/x86_64/encode'
require 'metasm/parse'

module Metasm
class X86_64
	def parse_parser_instruction(lexer, instr)
		case instr.raw.downcase
		when '.mode', '.bits'
			if tok = lexer.readtok and tok.type == :string and tok.raw == '64'
				lexer.skip_space
				raise instr, 'syntax error' if ntok = lexer.nexttok and ntok.type != :eol
			else
				raise instr, 'invalid cpu mode, 64bit only'
			end
		else super(lexer, instr)
		end
	end

	def parse_prefix(i, pfx)
		super(i, pfx) or (i.prefix[:sz] = 64 if pfx == 'code64')
	end

	# parses an arbitrary x64 instruction argument
	def parse_argument(lexer)
		# reserved names (registers/segments etc)
		@args_token ||= [Reg, SimdReg, SegReg, DbgReg, CtrlReg].map { |a| a.s_to_i.keys }.flatten.inject({}) { |h, e| h.update e => true }

		lexer.skip_space
		return if not tok = lexer.readtok

		if ret = ModRM.parse(lexer, tok, self)
			ret
		elsif @args_token[tok.raw]
			[Reg, SimdReg, SegReg, DbgReg, CtrlReg].each { |a|
				return a.from_str(tok.raw) if a.s_to_i.has_key? tok.raw
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
				Expression[expr.reduce] if expr
			end
		end
	end

	def parse_instruction_checkproto(i)
		# check ah vs rex prefix
		return if i.args.find { |a| a.kind_of? Reg and a.sz == 8 and a.val >= 16 and
				op = opcode_list.find { |op_| op_.name == i.opname } and
				((not op.props[:auto64] and i.args.find { |aa| aa.respond_to? :sz and aa.sz == 64 }) or
				 i.args.find { |aa| aa.kind_of? Reg and aa.val >= 8 and aa.val < 16 } or	# XXX mov ah, cr12...
				 i.args.grep(ModRM).find { |aa| (aa.b and aa.b.val >= 8 and aa.b.val < 16) or (aa.i and aa.i.val >= 8 and aa.i.val < 16) })
			}
		return if i.opname == 'movzx' and [[64, 16], [32, 32], [16, 32]].include? [i.args[0].sz, i.args[1].sz]
		super(i)
	end

	# check if the argument matches the opcode's argument spec
	def parse_arg_valid?(o, spec, arg)
		return if arg.kind_of? ModRM and ((arg.b and arg.b.val == 16 and arg.i) or (arg.i and arg.i.val == 16 and (arg.b or arg.s != 1)))
		return if arg.kind_of? Reg and arg.sz >= 32 and arg.val == 16	# eip/rip only in modrm
		return if o.props[:auto64] and arg.respond_to? :sz and arg.sz == 32
		if o.name == 'movsxd'
			return if not arg.kind_of? Reg and not arg.kind_of? ModRM
			arg.sz ||= 32
			if spec == :reg
				return arg.sz >= 32
			else
				return arg.sz == 32
			end
		elsif o.name == 'movzx'
			return if not arg.kind_of? Reg and not arg.kind_of? ModRM
			return arg.sz <= 32 if spec != :reg and not o.props[:argsz]
		end
		super(o, spec, arg)
	end
end
end
