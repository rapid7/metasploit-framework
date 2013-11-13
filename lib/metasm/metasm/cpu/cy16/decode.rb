#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/cy16/opcodes'
require 'metasm/decode'

module Metasm
class CY16
  def build_opcode_bin_mask(op)
    # bit = 0 if can be mutated by an field value, 1 if fixed by opcode
    op.bin_mask = 0
    op.fields.each { |f, off|
      op.bin_mask |= (@fields_mask[f] << off)
    }
    op.bin_mask ^= 0xffff
  end

  def build_bin_lookaside
    # sets up a hash byte value => list of opcodes that may match
    # opcode.bin_mask is built here
    lookaside = Array.new(256) { [] }
    opcode_list.each { |op|
      build_opcode_bin_mask op
      b   = (op.bin >> 8) & 0xff
      msk = (op.bin_mask >> 8) & 0xff
      for i in b..(b | (255^msk))
        lookaside[i] << op if i & msk == b & msk
      end
    }
    lookaside
  end

  def decode_findopcode(edata)
    di = DecodedInstruction.new self
    return if edata.ptr+2 > edata.length
    bin = edata.decode_imm(:u16, @endianness)
    edata.ptr -= 2
    return di if di.opcode = @bin_lookaside[(bin >> 8) & 0xff].find { |op|
      bin & op.bin_mask == op.bin & op.bin_mask
    }
  end


  def decode_instr_op_r(val, edata)
    bw = ((val & 0b1000) > 0 ? 1 : 2)
    case val & 0b11_0000
    when 0b00_0000
      Reg.new(val)
    when 0b01_0000
      if val == 0b01_1111
        Expression[edata.decode_imm(:u16, @endianness)]
      else
        Memref.new(Reg.new(8+(val&7)), nil, bw)
      end
    when 0b10_0000
      if val & 7 == 7
        Memref.new(nil, edata.decode_imm(:u16, @endianness), bw)
      else
        Memref.new(Reg.new(8+(val&7)), nil, bw, true)
      end
    when 0b11_0000
      Memref.new(Reg.new(8+(val&7)), edata.decode_imm(:u16, @endianness), bw)
    end

  end

  def decode_instr_op(edata, di)
    before_ptr = edata.ptr
    op = di.opcode
    di.instruction.opname = op.name
    bin = edata.decode_imm(:u16, @endianness)

    field_val = lambda { |f|
      if off = op.fields[f]
        (bin >> off) & @fields_mask[f]
      end
    }

    op.args.each { |a|
      di.instruction.args << case a
      when :rs, :rd; decode_instr_op_r(field_val[a], edata)
      when :o7; Expression[2*Expression.make_signed(field_val[a], 7)]
      when :x7; Expression[field_val[a]]
      when :u3; Expression[field_val[a]+1]
      else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
      end
    }

    di.instruction.args.reverse!

    di.bin_length += edata.ptr - before_ptr

    di
  rescue InvalidRD
  end

  def decode_instr_interpret(di, addr)
    if di.opcode.props[:setip] and di.opcode.args.last == :o7
      delta = di.instruction.args.last.reduce
      arg = Expression[[addr, :+, di.bin_length], :+, delta].reduce
      di.instruction.args[-1] = Expression[arg]
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

    mask = 0xffff

    opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
      binding = case op
      when 'mov'; lambda { |di, a0, a1| { a0 => Expression[a1] } }
      when 'add', 'adc', 'sub', 'sbc', 'and', 'xor', 'or', 'addi', 'subi'
        lambda { |di, a0, a1|
          e_op = { 'add' => :+, 'adc' => :+, 'sub' => :-, 'sbc' => :-, 'and' => :&,
             'xor' => :^, 'or' => :|, 'addi' => :+, 'subi' => :- }[op]
          ret = Expression[a0, e_op, a1]
          ret = Expression[ret, e_op, :flag_c] if op == 'adc' or op == 'sbb'
          # optimises eax ^ eax => 0
          # avoid hiding memory accesses (to not hide possible fault)
          ret = Expression[ret.reduce] if not a0.kind_of? Indirection
          { a0 => ret }
        }
      when 'cmp', 'test'; lambda { |di, *a| {} }
      when 'not'; lambda { |di, a0| { a0 => Expression[a0, :^, mask] } }
      when 'call'
        lambda { |di, a0| { :sp => Expression[:sp, :-, 2],
            Indirection[:sp, 2, di.address] => Expression[di.next_addr] }
        }
      when 'ret'; lambda { |di, *a| { :sp => Expression[:sp, :+, 2] } }
      # TODO callCC, retCC ...
      when /^j/; lambda { |di, *a| {} }
      end

      # TODO flags ?

      @backtrace_binding[op] ||= binding if binding
    }
    @backtrace_binding
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when Memref, Reg; arg.symbolic(di)
      else arg
      end
    }

    if binding = backtrace_binding[di.opcode.basename]
      bd = {}
      di.instruction.args.each { |aa| bd[aa.base.symbolic] = Expression[aa.base.symbolic, :+, aa.sz] if aa.kind_of?(Memref) and aa.autoincr }
      bd.update binding[di, *a]
    else
      puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
      # assume nothing except the 1st arg is modified
      case a[0]
      when Indirection, Symbol; { a[0] => Expression::Unknown }
      when Expression; (x = a[0].externals.first) ? { x => Expression::Unknown } : {}
      else {}
      end.update(:incomplete_binding => Expression[1])
    end
  end

  # patch a forward binding from the backtrace binding
  def fix_fwdemu_binding(di, fbd)
    case di.opcode.name
    when 'call'; fbd[Indirection[[:sp, :-, 2], 2]] = fbd.delete(Indirection[:sp, 2])
    end
    fbd
  end

  def get_xrefs_x(dasm, di)
    return [] if not di.opcode.props[:setip]

    return [Indirection[:sp, 2, di.address]] if di.opcode.name =~ /^r/

    case tg = di.instruction.args.first
    when Memref; [Expression[tg.symbolic(di)]]
    when Reg; [Expression[tg.symbolic(di)]]
    when Expression, ::Integer; [Expression[tg]]
    else
      puts "unhandled setip at #{di.address} #{di.instruction}" if $DEBUG
      []
    end
  end

  # checks if expr is a valid return expression matching the :saveip instruction
  def backtrace_is_function_return(expr, di=nil)
    expr = Expression[expr].reduce_rec
    expr.kind_of?(Indirection) and expr.len == 2 and expr.target == Expression[:sp]
  end

  # updates the function backtrace_binding
  # if the function is big and no specific register is given, do nothing (the binding will be lazily updated later, on demand)
  def backtrace_update_function_binding(dasm, faddr, f, retaddrlist, *wantregs)
    b = f.backtrace_binding

    bt_val = lambda { |r|
      next if not retaddrlist
      b[r] = Expression::Unknown
      bt = []
      retaddrlist.each { |retaddr|
        bt |= dasm.backtrace(Expression[r], retaddr, :include_start => true,
               :snapshot_addr => faddr, :origin => retaddr)
      }
      if bt.length != 1
        b[r] = Expression::Unknown
      else
        b[r] = bt.first
      end
    }

    if not wantregs.empty?
      wantregs.each(&bt_val)
    else
      bt_val[:sp]
    end

    b
  end

  # returns true if the expression is an address on the stack
  def backtrace_is_stack_address(expr)
    Expression[expr].expr_externals.include?(:sp)
  end

  # updates an instruction's argument replacing an expression with another (eg label renamed)
  def replace_instr_arg_immediate(i, old, new)
    i.args.map! { |a|
      case a
      when Expression; a == old ? new : Expression[a.bind(old => new).reduce]
      when Memref
        a.offset = (a.offset == old ? new : Expression[a.offset.bind(old => new).reduce]) if a.offset
        a
      else a
      end
    }
  end
end
end
