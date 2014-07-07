#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/ppc/opcodes'
require 'metasm/parse'

module Metasm
class PowerPC
# TODO
  def parse_arg_valid?(op, sym, arg)
    case sym
    when :ra, :rb, :rs, :rt; arg.kind_of?(GPR)
    when :fra, :frb, :frc, :frs, :frt; arg.kind_of?(FPR)
    when :ra_i16, :ra_i16s, :ra_i16q; arg.kind_of?(Memref)
    when :bd, :d, :ds, :dq, :si, :ui, :li, :sh, :mb, :me, :mb_, :me_, :u; arg.kind_of?(Expression)
    when :ba, :bf, :bfa, :bt; arg.kind_of?(CR)
    when :ign_bo_zzz, :ign_bo_z, :ign_bo_at, :ign_bo_at2, :aa, :lk, :oe, :rc, :l; # ?
    when :bb, :bh, :flm, :fxm, :l_, :l__, :lev, :nb, :sh_, :spr, :sr, :tbr, :th, :to
      # TODO
    else raise "internal error: mips arg #{sym.inspect}"
    end
  end

  def parse_argument(pgm)
    pgm.skip_space
    return if not tok = pgm.readtok
    if tok.type == :string
      return GPR.new(GPR.s_to_i[tok.raw]) if GPR.s_to_i[tok.raw]
      return SPR.new(SPR.s_to_i[tok.raw]) if SPR.s_to_i[tok.raw]
      return FPR.new(FPR.s_to_i[tok.raw]) if FPR.s_to_i[tok.raw]
      return CR.new(CR.s_to_i[tok.raw]) if CR.s_to_i[tok.raw]
      return MSR.new if tok.raw == 'msr'
    end
    pgm.unreadtok tok
    arg = Expression.parse pgm
    pgm.skip_space
    # check memory indirection: 'off(base reg)'	# XXX scaled index ?
    if arg and pgm.nexttok and pgm.nexttok.type == :punct and pgm.nexttok.raw == '('
      pgm.readtok
      pgm.skip_space_eol
      ntok = pgm.readtok
      raise tok, "Invalid base #{ntok}" unless ntok and ntok.type == :string and GPR.s_to_i[ntok.raw]
      base = GPR.new GPR.s_to_i[ntok.raw]
      pgm.skip_space_eol
      ntok = pgm.readtok
      raise tok, "Invalid memory reference, ')' expected" if not ntok or ntok.type != :punct or ntok.raw != ')'
      arg = Memref.new base, arg
    end
    arg
  end
end
end
