#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class MIPS
  def dbg_register_pc
    @dbg_register_pc ||= :pc
  end
  def dbg_register_flags
    @dbg_register_flags ||= :flags
  end

  def dbg_register_list
    @dbg_register_list ||= %w[z0 at v0 v1 a0 a1 a2 a3
          t0 t1 t2 t3 t4 t5 t6 t7
          s0 s1 s2 s3 s4 s5 s6 s7
          t8 t9 k0 k1 gp sp fp ra
          sr mullo mulhi badva cause pc].map { |r| r.to_sym }
  end

  def dbg_flag_list
    @dbg_flag_list ||= []
  end

  def dbg_register_size
    @dbg_register_size ||= Hash.new(@size)
  end

  def dbg_need_stepover(dbg, addr, di)
    di and di.opcode.props[:saveip]
  end

  def dbg_end_stepout(dbg, addr, di)
    di and di.opcode.name == 'foobar'	# TODO
  end
end
end
