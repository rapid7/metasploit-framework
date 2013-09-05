#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/opcodes'

module Metasm
class X86_64
  def dbg_register_pc
    @dbg_register_pc ||= :rip
  end
  def dbg_register_flags
    @dbg_register_flags ||= :rflags
  end

  def dbg_register_list 
    @dbg_register_list ||= [:rax, :rbx, :rcx, :rdx, :rsi, :rdi, :rbp, :rsp, :r8, :r9, :r10, :r11, :r12, :r13, :r14, :r15, :rip]
  end

  def dbg_register_size
    @dbg_register_size ||= Hash.new(64).update(:cs => 16, :ds => 16, :es => 16, :fs => 16, :gs => 16)
  end

  def dbg_func_arg(dbg, argnr)
    if dbg.class.name =~ /win/i
      list = [:rcx, :rdx, :r8, :r9]
      off = 0x20
    else
      list = [:rdi, :rsi, :rdx, :rcx, :r8, :r9]
      off = 0
    end
    if r = list[argnr]
      dbg.get_reg_value(r)
    else
      argnr -= list.length
      dbg.memory_read_int(Expression[:esp, :+, off + 8 + 8*argnr])
    end
  end
  def dbg_func_arg_set(dbg, argnr, arg)
    if dbg.class.name =~ /win/i
      list = []
      off = 0x20
    else
      list = []
      off = 0
    end
    if r = list[argnr]
      dbg.set_reg_value(r, arg)
    else
      argnr -= list.length
      dbg.memory_write_int(Expression[:esp, :+, off + 8 + 8*argnr], arg)
    end
  end

  # what's left is inherited from Ia32
end
end
