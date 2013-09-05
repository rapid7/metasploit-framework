#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/opcodes'

module Metasm
class Ia32
  def dbg_register_pc
    @dbg_register_pc ||= :eip
  end
  def dbg_register_sp
    @dbg_register_sp ||= dbg_register_list[7]
  end
  def dbg_register_flags
    @dbg_register_flags ||= :eflags
  end

  def dbg_register_list 
    @dbg_register_list ||= [:eax, :ebx, :ecx, :edx, :esi, :edi, :ebp, :esp, :eip]
  end

  def dbg_register_size
    @dbg_register_size ||= Hash.new(32).update(:cs => 16, :ds => 16, :es => 16, :fs => 16, :gs => 16)
  end

  def dbg_flag_list
    @dbg_flag_list ||= [:c, :p, :a, :z, :s, :i, :d, :o]
  end

  DBG_FLAGS = { :c => 0, :p => 2, :a => 4, :z => 6, :s => 7, :t => 8, :i => 9, :d => 10, :o => 11 }
  def dbg_get_flag(dbg, f)
    (dbg.get_reg_value(dbg_register_flags) >> DBG_FLAGS[f]) & 1
  end
  def dbg_set_flag(dbg, f)
    fl = dbg.get_reg_value(dbg_register_flags)
    fl |= 1 << DBG_FLAGS[f]
    dbg.set_reg_value(dbg_register_flags, fl)
  end
  def dbg_unset_flag(dbg, f)
    fl = dbg.get_reg_value(dbg_register_flags)
    fl &= ~(1 << DBG_FLAGS[f])
    dbg.set_reg_value(dbg_register_flags, fl)
  end

  def dbg_enable_singlestep(dbg)
    dbg_set_flag(dbg, :t)
  end
  def dbg_disable_singlestep(dbg)
    dbg_unset_flag(dbg, :t)
  end

  def dbg_enable_bp(dbg, bp)
    case bp.type
    when :bpx; dbg_enable_bpx( dbg, bp)
    else       dbg_enable_bphw(dbg, bp)
    end
  end

  def dbg_disable_bp(dbg, bp)
    case bp.type
    when :bpx; dbg_disable_bpx( dbg, bp)
    else       dbg_disable_bphw(dbg, bp)
    end
  end

  def dbg_enable_bpx(dbg, bp)
    bp.internal[:previous] ||= dbg.memory[bp.address, 1]
    dbg.memory[bp.address, 1] = "\xcc"
  end

  def dbg_disable_bpx(dbg, bp)
    dbg.memory[bp.address, 1] = bp.internal[:previous]
  end

  # allocate a debug register for a hwbp by checking the list of hwbp existing in dbg
  def dbg_alloc_bphw(dbg, bp)
    if not bp.internal[:dr]
      may = [0, 1, 2, 3]
      dbg.breakpoint_thread.values.each { |bb| may.delete bb.internal[:dr] }
      raise 'alloc_bphw: no free debugregister' if may.empty?
      bp.internal[:dr] = may.first
    end
    bp.internal[:type] ||= :x
    bp.internal[:len]  ||= 1
    bp.internal[:dr]
  end

  def dbg_enable_bphw(dbg, bp)
    nr = dbg_alloc_bphw(dbg, bp)
    dr7 = dbg[:dr7]
    l = { 1 => 0, 2 => 1, 4 => 3, 8 => 2 }[bp.internal[:len]]
    rw = { :x => 0, :w => 1, :r => 3 }[bp.internal[:type]]
    raise "enable_bphw: invalid breakpoint #{bp.inspect}" if not l or not rw
    dr7 &= ~((15 << (16+4*nr)) | (3 << (2*nr)))	# clear
    dr7 |= ((l << 2) | rw) << (16+4*nr)	# set drN len/rw
    dr7 |= 3 << (2*nr)	# enable global/local drN

    dbg["dr#{nr}"] = bp.address
    dbg[:dr7] = dr7
  end

  def dbg_disable_bphw(dbg, bp)
    nr = bp.internal[:dr]
    dr7 = dbg[:dr7]
    dr7 &= ~(3 << (2*nr))
    dbg[:dr7] = dr7
  end

  def dbg_check_pre_run(dbg)
    if dbg[:dr6] == 0 and dbg[:dr7] == 0
      dbg[:dr7] = 0x10000	# some OS (eg Windows) only return dr6 if dr7 != 0
    end
    dbg[:dr6] = 0
  end

  def dbg_evt_bpx(dbg, b)
    if b.address == dbg.pc-1
      dbg.pc -= 1
    end
      end

  def dbg_find_bpx(dbg)
    return if dbg[:dr6] & 0x4000 != 0
    pc = dbg.pc
    dbg.breakpoint[pc-1] || dbg.breakpoint[pc]
    end

  def dbg_find_hwbp(dbg)
    dr6 = dbg[:dr6]
    return if dr6 & 0xf == 0
    dn = (0..3).find { |n| dr6 & (1 << n) }
    dbg.breakpoint_thread.values.find { |b| b.internal[:dr] == dn }
  end

  def dbg_need_stepover(dbg, addr, di)
    di and ((di.instruction.prefix and di.instruction.prefix[:rep]) or di.opcode.props[:saveip])
  end

  def dbg_end_stepout(dbg, addr, di)
    di and di.opcode.name == 'ret'
  end

  # return (yield) a list of [addr, symbolic name]
  def dbg_stacktrace(dbg, rec=500)
    ret = []
    s = dbg.addrname!(dbg.pc)
    yield(dbg.pc, s) if block_given?
    ret << [dbg.pc, s]
    fp = dbg.get_reg_value(dbg_register_list[6])
    stack = dbg.get_reg_value(dbg_register_list[7]) - 8
    while fp > stack and fp <= stack+0x10000 and rec != 0
      rec -= 1
      ra = dbg.resolve_expr Indirection[fp+4, 4]
      s = dbg.addrname!(ra)
      yield(ra, s) if block_given?
      ret << [ra, s]
      stack = fp	# ensure we walk the stack upwards
      fp = dbg.resolve_expr Indirection[fp, 4]
    end
    ret
  end

  # retrieve the current function return value
  # only valid at function exit
  def dbg_func_retval(dbg)
    dbg.get_reg_value(dbg_register_list[0])
  end
  def dbg_func_retval_set(dbg, val)
    dbg.set_reg_value(dbg_register_list[0], val)
  end

  # retrieve the current function return address
  # to be called only on entry of the subfunction
  def dbg_func_retaddr(dbg)
    dbg.memory_read_int(dbg_register_list[7])
  end
  def dbg_func_retaddr_set(dbg, ret)
    dbg.memory_write_int(dbg_register_list[7], ret)
  end

  # retrieve the current function arguments
  # only valid at function entry (eg right after the call)
  def dbg_func_arg(dbg, argnr)
    dbg.memory_read_int(Expression[:esp, :+, 4*(argnr+1)])
  end
  def dbg_func_arg_set(dbg, argnr, arg)
    dbg.memory_write_int(Expression[:esp, :+, 4*(argnr+1)], arg)
  end
end
end
