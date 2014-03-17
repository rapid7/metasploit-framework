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

  # needed due to how ruby inheritance works wrt constants
  def parse_argregclasslist
    [Reg, SimdReg, SegReg, DbgReg, CtrlReg, FpReg]
  end
  # same inheritance sh*t
  def parse_modrm(lex, tok, cpu)
    ModRM.parse(lex, tok, cpu)
  end

  def parse_instruction_checkproto(i)
    # check ah vs rex prefix
    return if i.args.find { |a| a.kind_of? Reg and a.sz == 8 and a.val >= 16 and
        op = opcode_list.find { |op_| op_.name == i.opname } and
        ((not op.props[:auto64] and i.args.find { |aa| aa.respond_to? :sz and aa.sz == 64 }) or
         i.args.find { |aa| aa.kind_of? Reg and aa.val >= 8 and aa.val < 16 } or	# XXX mov ah, cr12...
         i.args.grep(ModRM).find { |aa| (aa.b and aa.b.val >= 8 and aa.b.val < 16) or (aa.i and aa.i.val >= 8 and aa.i.val < 16) })
      }
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
        return if not arg.kind_of? Reg
        return arg.sz >= 32
      else
        return arg.sz == 32
      end
    end
    super(o, spec, arg)
  end
end
end
