#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/bpf/opcodes'
require 'metasm/decode'

module Metasm
class BPF
  def build_bin_lookaside
    opcode_list.inject({}) { |h, op| h.update op.bin => op }
  end

  # tries to find the opcode encoded at edata.ptr
  def decode_findopcode(edata)
    return if edata.ptr > edata.data.length-8
    di = DecodedInstruction.new self
    code = edata.data[edata.ptr, 2].unpack('v')[0]
    return di if di.opcode = @bin_lookaside[code]
  end

  def decode_instr_op(edata, di)
    op = di.opcode
    di.instruction.opname = op.name
    di.bin_length = 8
    code, jt, jf, k = edata.read(8).unpack('vCCV')

    op.args.each { |a|
      di.instruction.args << case a
      when :k;    Expression[k]
      when :x;    Reg.new(:x)
      when :a;    Reg.new(:a)
      when :len;  Reg.new(:len)
      when :p_k;  PktRef.new(nil, Expression[k], op.props[:msz])
      when :p_xk; PktRef.new(Reg.new(:x), Expression[k], op.props[:msz])
      when :m_k;  MemRef.new(nil, Expression[4*k], 4)
      when :jt;   Expression[jt]
      when :jf;   Expression[jf]
      else raise "unhandled arg #{a}"
      end
    }

    # je a, x, 0, 12 -> jne a, x, 12
    # je a, x, 12, 0 -> je a, x, 12
    if op.args[2] == :jt and di.instruction.args[2] == Expression[0]
      di.opcode = op.dup
      di.opcode.props.delete :stopexec
      di.instruction.opname = { 'jg' => 'jle', 'jge' => 'jl', 'je' => 'jne', 'jtest' => 'jntest' }[di.instruction.opname]
      di.instruction.args.delete_at(2)
    elsif op.args[3] == :jf and di.instruction.args[3] == Expression[0]
      di.opcode = op.dup
      di.opcode.props.delete :stopexec
      di.instruction.args.delete_at(3)
    end

    di
  end

  def decode_instr_interpret(di, addr)
    if di.opcode.props[:setip]
      delta = di.instruction.args[-1].reduce + 1
      arg = Expression[addr, :+, 8*delta].reduce
      di.instruction.args[-1] = Expression[arg]

      if di.instruction.args.length == 4
        delta = di.instruction.args[2].reduce + 1
        arg = Expression[addr, :+, 8*delta].reduce
        di.instruction.args[2] = Expression[arg]
      end
    end

    di
  end

  # hash opcode_name => lambda { |dasm, di, *symbolic_args| instr_binding }
  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end
  def backtrace_binding=(b) @backtrace_binding = b end

  # populate the @backtrace_binding hash with default values
  def init_backtrace_binding
    @backtrace_binding ||= {}

    opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
      binding = case op
      when 'mov'; lambda { |di, a0, a1| { a0 => Expression[a1] } }
      when 'add'; lambda { |di, a0, a1| { a0 => Expression[a0, :+, a1] } }
      when 'sub'; lambda { |di, a0, a1| { a0 => Expression[a0, :-, a1] } }
      when 'mul'; lambda { |di, a0, a1| { a0 => Expression[a0, :*, a1] } }
      when 'div'; lambda { |di, a0, a1| { a0 => Expression[a0, :/, a1] } }
      when 'shl'; lambda { |di, a0, a1| { a0 => Expression[a0, :<<, a1] } }
      when 'shr'; lambda { |di, a0, a1| { a0 => Expression[a0, :>>, a1] } }
      when 'neg'; lambda { |di, a0| { a0 => Expression[:-, a0] } }
      when 'msh'; lambda { |di, a0, a1| { a0 => Expression[[a1, :&, 0xf], :<<, 2] } }
      when 'jmp', 'jg', 'jge', 'je', 'jtest', 'ret'; lambda { |di, *a| { } }
      end
      @backtrace_binding[op] ||= binding if binding
    }

    @backtrace_binding
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when PktRef, MemRef, Reg; arg.symbolic(di)
      else arg
      end
    }

    if binding = backtrace_binding[di.opcode.name]
      binding[di, *a]
    else
      puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
      {:incomplete_binding => Expression[1]}
    end
  end

  def get_xrefs_x(dasm, di)
    return [] if not di.opcode.props[:setip]

    if di.instruction.args.length == 4
      di.instruction.args[-2, 2]
    else
      di.instruction.args[-1, 1]
    end
  end

  # updates an instruction's argument replacing an expression with another (eg label renamed)
  def replace_instr_arg_immediate(i, old, new)
    i.args.map! { |a|
      case a
      when Expression; a == old ? new : Expression[a.bind(old => new).reduce]
      else a
      end
    }
  end
end
end
