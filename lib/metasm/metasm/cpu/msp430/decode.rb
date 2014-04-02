#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/msp430/opcodes'
require 'metasm/decode'

module Metasm
class MSP430
  def build_opcode_bin_mask(op)
    op.bin_mask = 0
    op.fields.each_key { |f|
      op.bin_mask |= @fields_mask[f] << @fields_shift[f]
    }
    op.bin_mask ^= 0xffff
  end

  def build_bin_lookaside
    lookaside = Array.new(256) { [] }
    opcode_list.each { |op|
      build_opcode_bin_mask op
      b   = (op.bin >> 8) & 255
      msk = (op.bin_mask >> 8) & 255

      for i in b..(b | (255^msk))
        lookaside[i] << op if i & msk == b & msk
      end
    }
    lookaside
  end

  def decode_findopcode(edata)
    di = DecodedInstruction.new(self)
    val = edata.decode_imm(:u16, @endianness)
    edata.ptr -= 2
    di.opcode = @bin_lookaside[(val >> 8) & 0xff].find { |opcode| (val & opcode.bin_mask) == opcode.bin }
    di if di.opcode
  end

  def decode_instr_op(edata, di)
    before_ptr = edata.ptr
    op = di.opcode
    di.instruction.opname = op.name
    val = edata.decode_imm(:u16, @endianness)

    field_val = lambda{ |f|
      (val >> @fields_shift[f]) & @fields_mask[f]
    }

    # must decode rs first
    vals = {}
    ([:rs, :rd, :r_pc] & op.args).each { |a|
      mod = { :rs => :as, :rd => :ad, :r_pc => :ad }[a]
      mod = :as if mod == :ad and not op.fields[mod]	# addop_macro1 -> rs + ad

      if a == :r_pc
        r = Reg.new(0)
      else
        r = Reg.new(field_val[a])
      end

      w = op.props[:byte] ? 1 : 2

      case field_val[mod]
      when 0
        if r.i == 3 and a == :rs
          vals[a] = Expression[0]
        else
          vals[a] = r
        end
      when 1
        if r.i == 3 and a == :rs
          vals[a] = Expression[1]
        else
          imm = edata.decode_imm(:u16, @endianness)
          r = nil if r.i == 2	# [imm]
          vals[a] = Memref.new(r, imm, w)
        end
      when 2
        if r.i == 3
          vals[a] = Expression[2]
        elsif r.i == 2
          vals[a] = Expression[4]
        else
          vals[a] = Memref.new(r, 0, w)
        end
      when 3
        if r.i == 3
          vals[a] = Expression[-1]
        elsif r.i == 2
          vals[a] = Expression[8]
        elsif r.i == 0 # pc++
          # XXX order wrt other edata.decode_imm ?
          vals[a] = Expression[edata.decode_imm(:u16, @endianness)]
        else
          vals[a] = Memref.new(r, 0, w, true)
        end
      end
    }

    op.args.each { |a|
      di.instruction.args << case a
      when :joff; Expression[2 * Expression.make_signed(field_val[a], 10)]
      when :rs, :rd, :r_pc; vals[a]
      else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
      end
    }

    di.bin_length += edata.ptr - before_ptr

    return if edata.ptr > edata.length

    di
  end

  def decode_instr_interpret(di, addr)
    if di.opcode.props[:setip] and di.opcode.name =~ /^j/
      delta = di.instruction.args.last.reduce
      arg = Expression[[addr, :+, di.bin_length], :+, delta].reduce
      di.instruction.args[-1] = Expression[arg]
    end

    di
  end

  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end

  def init_backtrace_binding
    @backtrace_binding ||= {}

    opcode_list.map { |ol| ol.name }.uniq.each { |op|
      @backtrace_binding[op] ||= case op
      when 'mov'; lambda { |di, a0, a1| { a0 => Expression[a1] }}
      when 'cmp', 'test'; lambda { |di, *a| {} }	# TODO
      when 'add', 'adc' ; lambda { |di, a0, a1| { a0 => Expression[a0, :+, a1] } }
      when 'sub', 'sbc';  lambda { |di, a0, a1| { a0 => Expression[a0, :-, a1] } }
      when 'and'; lambda { |di, a0, a1| { a0 => Expression[a0, :&, a1] } }
      when 'or';  lambda { |di, a0, a1| { a0 => Expression[a0, :|, a1] } }
      when 'xor'; lambda { |di, a0, a1| { a0 => Expression[a0, :^, a1] } }
      when 'push'; lambda { |di, a0| { Indirection[:sp, 2] => Expression[a0],
               :sp => Expression[:sp, :-, 2] } }
      when 'call'; lambda { |di, a0| { Indirection[:sp, 2] => Expression[di.next_addr],
               :sp => Expression[:sp, :-, 2] } }
      when 'pop';  lambda { |di, a0| { a0 => Expression[Indirection[:sp, 2]],
               :sp => Expression[:sp, :+, 2] } }
      when 'ret';  lambda { |di| { :sp => Expression[:sp, :+, 2] } }
      when 'reti'; lambda { |di| { :sp => Expression[:sp, :+, 4] } }
      when /^j/; lambda { |di, a0| {} }
      end
    }

    @backtrace_binding
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when Reg; arg.symbolic
      when Memref; arg.symbolic(di.address)
      else arg
      end
    }

    if binding = backtrace_binding[di.opcode.basename]
      bd = binding[di, *a] || {}
      di.instruction.args.grep(Memref).each { |m|
        next unless r = m.base and m.postincr
        r = m.base.symbolic
        bd[r] ||= Expression[r, :+, m.size]
      }
      bd
    else
      puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
      { :incomplete_binding => Expression[1] }
    end
  end

  def get_xrefs_x(dasm, di)
    return [] if not di.opcode.props[:setip]

    case di.instruction.opname
    when 'ret'
      return [Indirection[:sp, 2, di.address]]
    when 'reti'
      return [Indirection[[:sp, :+, 2], 2, di.address]]
    end

    # XXX add pc, 42 ?
    val = di.instruction.args[0]
    case val
    when Reg; val = val.symbolic
    when Memref; val = val.symbolic(di.address)
    end

    [Expression[val]]
  end

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

  def replace_instr_arg_immediate(i, old, new)
    i.args.map! { |a|
      case a
      when Expression; a == old ? new : Expression[a.bind(old => new).reduce]
      when Memref
        a.base = (a.base == old ? new : Expression[a.base.bind(old => new).reduce]) if a.base.kind_of?(Expression)
        a
      else a
      end
    }
  end
end
end
