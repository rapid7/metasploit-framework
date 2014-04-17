#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/bpf/main'

module Metasm

class BPF
  def addop(name, bin, *args)
    o = Opcode.new name, bin
    args.each { |a|
      o.args << a if @valid_args[a]
      o.props.update a if a.kind_of?(::Hash)
    }
    @opcode_list << o
  end

  def addop_ldx(bin, src)
    addop 'mov', bin | 0x00, :a, src
    addop 'mov', bin | 0x01, :x, src
  end

  def addop_ldsz(bin, src)
    addop 'mov', bin | 0x00, :a, src, :msz => 4
    addop 'mov', bin | 0x08, :a, src, :msz => 2
    addop 'mov', bin | 0x10, :a, src, :msz => 1
  end

  def addop_alu(name, bin)
    addop name, bin | 0x04, :a, :k
    addop name, bin | 0x0C, :a, :x
  end

  def addop_j(name, bin)
    addop name, bin | 0x05 | 0x00, :a, :k, :jt, :jf, :setip => true, :stopexec => true
    addop name, bin | 0x05 | 0x08, :a, :x, :jt, :jf, :setip => true, :stopexec => true
  end

  def init_bpf
    @opcode_list = []
    [:a, :k, :x, :len, :m_k, :p_k, :p_xk, :jt, :jf].each { |a| @valid_args[a] = true }

    # LD/ST
    addop_ldx  0x00, :k
    addop_ldsz 0x20, :p_k
    addop_ldsz 0x40, :p_xk
    addop_ldx  0x60, :m_k
    addop_ldx  0x80, :len
    addop 'msh', 0xB1, :x, :p_k, :msz => 1
    addop 'mov', 0x02, :m_k, :a
    addop 'mov', 0x03, :m_k, :x

    # ALU
    addop_alu 'add', 0x00
    addop_alu 'sub', 0x10
    addop_alu 'mul', 0x20
    addop_alu 'div', 0x30
    addop_alu 'or',  0x40
    addop_alu 'and', 0x50
    addop_alu 'shl', 0x60
    addop_alu 'shr', 0x70
    addop 'neg', 0x84, :a

    # JMP
    addop   'jmp',  0x05, :k, :setip => true, :stopexec => true
    addop_j 'je',   0x10
    addop_j 'jg',   0x20
    addop_j 'jge',  0x30
    addop_j 'jtest',0x40
    addop   'ret',  0x06, :k, :stopexec => true
    addop   'ret',  0x16, :a, :stopexec => true

    addop 'mov', 0x07, :x, :a
    addop 'mov', 0x87, :a, :x
  end

  alias init_latest init_bpf
end
end
