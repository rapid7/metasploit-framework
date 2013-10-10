#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ppc/opcodes'
require 'metasm/decode'

module Metasm
class PowerPC
  def build_opcode_bin_mask(op)
    # bit = 0 if can be mutated by an field value, 1 if fixed by opcode
    return if not op.bin.kind_of? Integer
    op.bin_mask = 0
    op.args.each { |f|
      op.bin_mask |= @fields_mask[f] << @fields_shift[f]
    }
    op.bin_mask = 0xffff_ffff ^ op.bin_mask
  end

  def build_bin_lookaside
    lookaside = Array.new(256) { [] }
    opcode_list.each { |op|
      next if not op.bin.kind_of? Integer
      build_opcode_bin_mask op

      b   = op.bin >> 24
      msk = op.bin_mask >> 24

      for i in b..(b | (255^msk))
        next if i & msk != b & msk
        lookaside[i] << op
      end
    }
    lookaside
  end

  def decode_findopcode(edata)
    return if edata.ptr >= edata.data.length
    di = DecodedInstruction.new(self)
    val = edata.decode_imm(:u32, @endianness)
    edata.ptr -= 4
    di if di.opcode = @bin_lookaside[val >> 24].find { |op|
      (op.bin & op.bin_mask) == (val & op.bin_mask)
    }
  end

  def decode_instr_op(edata, di)
    before_ptr = edata.ptr
    op = di.opcode
    di.instruction.opname = op.name
    val = edata.decode_imm(:u32, @endianness)

    field_val = lambda { |f|
      r = (val >> @fields_shift[f]) & @fields_mask[f]
      case f
      when :bd, :d, :ds, :dq, :si, :ui; r = Expression.make_signed(r<<@fields_shift[f], 16)
      when :li; r = Expression.make_signed(r<<@fields_shift[f], 26)
      else r
      end
    }

    op.args.each { |a|
      di.instruction.args << case a
      when :ra, :rb, :rs, :rt; GPR.new field_val[a]
      when :fra, :frb, :frc, :frs, :frt; FPR.new field_val[a]
      when :ra_i16, :ra_i16s, :ra_i16q
        i = field_val[{:ra_i16 => :d, :ra_i16s => :ds, :ra_i16q => :dq}[a]]
               Memref.new GPR.new(field_val[:ra]), Expression[i]
      when :bd, :d, :ds, :dq, :si, :ui, :li, :sh, :ma, :mb, :me, :ma_, :mb_, :me_; Expression[field_val[a]]
      when :ign_bo_zzz, :ign_bo_z, :ign_bo_at, :ign_bo_at2, :ign_bi, :aa, :lk, :oe, :rc, :l; next
      else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
      end
    }
    di.bin_length += edata.ptr - before_ptr

    decode_aliases(di.instruction)

    di
  end

  def decode_aliases(i)
    case i.opname
    when /^n?or\.?$/
      if i.args[1] == i.args[2]
         i.args.pop
         i.opname = {'or' => 'mr', 'or.' => 'mr.', 'nor' => 'not', 'nor.' => 'not.'}[i.opname]
      end
    when /^addi/
      if a = i.args[2].reduce and a.kind_of? Integer and a < 0
        i.args[2] = Expression[-a]
        i.opname = i.opname.sub('addi', 'subi')
      end
    end

    case i.opname
    when /^(add|sub|xor|and|or|div|mul|nand)/
      if i.args.length == 3 and i.args[0] == i.args[1]
        i.args.shift
      end
    end

  end

  # converts relative branch offsets to absolute addresses
  # else just add the offset +off+ of the instruction + its length (off may be an Expression)
  # assumes edata.ptr points just after the instruction (as decode_instr_op left it)
  # do not call twice on the same di !
 	def decode_instr_interpret(di, addr)
    if di.opcode.props[:setip] and di.instruction.args.last.kind_of? Expression and di.opcode.name[0] != ?t and di.opcode.name[-1] != ?a
      arg = Expression[addr, :+, di.instruction.args.last].reduce
      di.instruction.args[-1] = Expression[arg]
    end

    di
  end

  # TODO
  def backtrace_update_function_binding(dasm, faddr, f, retaddrlist, *wantregs)
    retaddrlist.to_a.map! { |retaddr| dasm.decoded[retaddr] ? dasm.decoded[retaddr].block.list.last.address : retaddr }
    b = f.backtrace_binding

    bt_val = lambda { |r|
      bt = []
      retaddrlist.to_a.each { |retaddr|
        bt |= dasm.backtrace(Expression[r], retaddr,
          :include_start => true, :snapshot_addr => faddr, :origin => retaddr)
      }
      b[r] = ((bt.length == 1) ? bt.first : Expression::Unknown)
    }
    wantregs = GPR::Sym if wantregs.empty?
    wantregs.map { |r| r.to_sym }.each(&bt_val)

    #puts "update_func_bind: #{Expression[faddr]} has sp -> #{b[:$sp]}" if not Expression[b[:$sp], :-, :$sp].reduce.kind_of?(::Integer) if $VERBOSE
  end

  def backtrace_is_function_return(expr, di=nil)
    expr.reduce_rec == :lr
  end

  def backtrace_is_stack_address(expr)
    Expression[expr].expr_externals.include? :sp
  end

  def replace_instr_arg_immediate(i, old, new)
    i.args.map! { |a|
      case a
      when Expression; a == old ? new : Expression[a.bind(old => new).reduce]
      when Memref
        a.offset = (a.offset == old ? new : Expression[a.offset.bind(old => new).reduce]) if a.offset.kind_of? Expression
        a
      else a
      end
    }
  end

  def disassembler_default_func
    df = DecodedFunction.new
    df.backtrace_binding = (0..31).inject({}) { |h, r| r != 1 ? h.update("r#{r}".to_sym => Expression::Unknown) : h }
    df.backtracked_for = [BacktraceTrace.new(Expression[:lr], :default, Expression[:lr], :x)]
    df.btfor_callback = lambda { |dasm, btfor, funcaddr, calladdr|
      if funcaddr != :default
        btfor
      elsif di = dasm.decoded[calladdr] and di.opcode.props[:saveip]
        btfor
      else []
      end
    }
    df
  end

  # hash opname => lambda { |di, *sym_args| binding }
  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end
  def backtrace_binding=(b) @backtrace_binding = b end

  def init_backtrace_binding
    @backtrace_binding ||= {}
    opcode_list.map { |ol| ol.name }.uniq.each { |op|
      binding = case op
      when 'mr', 'li', 'la'; lambda { |di, a0, a1| { a0 => Expression[a1] } }
      when 'lis'; lambda { |di, a0, a1| { a0 => Expression[a1, :<<, 16] } }
      when 'mtctr'; lambda { |di, a0| { :ctr => Expression[a0] } }
      when 'mfctr'; lambda { |di, a0| { a0 => Expression[:ctr] } }
      when 'mtlr'; lambda { |di, a0| { :lr => Expression[a0] } }
      when 'mflr'; lambda { |di, a0| { a0 => Expression[:lr] } }
      when 'lwzu'; lambda { |di, a0, m|
        ret = { a0 => Expression[m] }
        ptr = m.pointer.externals.grep(Symbol).first
        ret[ptr] = m.pointer if ptr != a0
        ret
             }
      when 'lwz'; lambda { |di, a0, m| { a0 => Expression[m] } }
      when 'stwu'; lambda { |di, a0, m|
        { m => Expression[a0], m.pointer.externals.grep(Symbol).first => m.pointer }
             }
      when 'stw'; lambda { |di, a0, m| { m => Expression[a0] } }
      when 'rlwinm'; lambda { |di, a0, a1, sh, mb, me|
        mb, me = mb.reduce, me.reduce
        cpmsk = (1<<@size) - 1
        a1 = Expression[a1, :&, cpmsk]
        rol = Expression[[a1, :<<, sh], :|, [a1, :>>, [@size, :-, sh]]]
        if mb == me+1
          msk = cpmsk
        elsif mb < me+1
          msk = (((1 << ((me+1)-mb)) - 1) << (@size-(me+1)))
        else
          msk = (((1 << (mb-(me+1))) - 1) << (@size-mb)) ^ cpmsk
        end
        { a0 => Expression[Expression[rol, :&, msk].reduce] }
      }

      when 'add', 'addi', 'add.', 'addi.'; lambda { |di, *a| { a[0] => Expression[a[-2], :+, a[-1]] } }
      when 'addis', 'addis.'; lambda { |di, *a| { a[0] => Expression[a[-2], :+, [a[-1], :<<, 16]] } }
      when 'sub', 'subi', 'sub.', 'subi.'; lambda { |di, *a| { a[0] => Expression[a[-2], :-, a[-1]] } }
      when 'subis', 'subis.'; lambda { |di, *a| { a[0] => Expression[a[-2], :-, [a[-1], :<<, 16]] } }
      when /^b.*la?$/; lambda { |di, *a| { :lr => Expression[di.next_addr] } }
      when 'nop', /^cmp/, /^b/; lambda { |di, *a| {} }
      end

      @backtrace_binding[op] ||= binding if binding
    }
    @backtrace_binding
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when Memref; arg.symbolic(di.address)
      when Reg; arg.symbolic
      else arg
      end
    }

    binding = if binding = backtrace_binding[di.instruction.opname]
      binding[di, *a]
    else
      puts "unknown instruction to emu #{di}" if $VERBOSE
      {}
    end

    binding
  end

  def get_xrefs_x(dasm, di)
    return [] if not di.opcode.props[:setip]

    arg = case di.instruction.opname
          when 'bctr', 'bctrl'; :ctr
          when 'blr', 'blrl'; :lr
          else di.instruction.args.last
          end

    [Expression[
    case arg
    when Memref; Indirection[[arg.base.to_s.to_sym, :+, arg.offset], @size/8, di.address]
    when Reg; arg.to_s.to_sym
    else arg
    end]]
  end
end
end
