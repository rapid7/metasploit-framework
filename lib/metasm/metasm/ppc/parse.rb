#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ppc/opcodes'
require 'metasm/parse'

module Metasm
class PowerPC
# TODO
  def parse_arg_valid?(op, sym, arg)
    # special case for lw reg, imm32(reg) ? (pseudo-instr, need to convert to 'lui t0, up imm32  ori t0 down imm32  add t0, reg  lw reg, 0(t0)
    case sym
    when :rs, :rt, :rd;   arg.kind_of? Reg
    when :sa, :i16, :i20, :i26; arg.kind_of? Expression
    when :rs_i16;         arg.kind_of? Memref
    when :ft;             arg.kind_of? FpReg
    else raise "internal error: mips arg #{sym.inspect}"
    end
  end

  def parse_argument(pgm)
    pgm.skip_space
    return if not tok = pgm.nexttok
    if tok.type == :string and Reg.s_to_i[tok.raw]
      pgm.readtok
      arg = Reg.new Reg.s_to_i[tok.raw]
    elsif tok.type == :string and FpReg.s_to_i[tok.raw]
      pgm.readtok
      arg = FpReg.new FpReg.s_to_i[tok.raw]
    else
      arg = Expression.parse pgm
      pgm.skip_space
      # check memory indirection: 'off(base reg)'	# XXX scaled index ?
      if arg and pgm.nexttok and pgm.nexttok.type == :punct and pgm.nexttok.raw == '('
        pgm.readtok
        pgm.skip_space_eol
        ntok = pgm.readtok
        raise tok, "Invalid base #{ntok}" unless ntok and ntok.type == :string and Reg.s_to_i[ntok.raw]
        base = Reg.new Reg.s_to_i[ntok.raw]
        pgm.skip_space_eol
        ntok = pgm.readtok
        raise tok, "Invalid memory reference, ')' expected" if not ntok or ntok.type != :punct or ntok.raw != ')'
        arg = Memref.new base, arg
      end
    end
    arg
  end
end
end
