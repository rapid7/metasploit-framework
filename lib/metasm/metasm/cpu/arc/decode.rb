#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/arc/opcodes'
require 'metasm/decode'

module Metasm
class ARC
  def major_opcode(val, sz = 16)
    return val >> (sz == 16 ? 0xB : 0x1B)
  end

  def sub_opcode(val)
    return ((val >> 16) & 0x3f)
  end

  def build_opcode_bin_mask(op, sz)
    op.bin_mask = 0
    op.args.each { |f| op.bin_mask |= @fields_mask[f] << @fields_shift[f]}
    op.bin_mask = ((1 << sz)-1) ^ op.bin_mask
  end

  def build_bin_lookaside
    bin_lookaside = {}
    opcode_list.each{|mode,oplist|
      lookaside = {}
      # 2nd level to speed up lookaside for major 5
      lookaside[5] = {}
      oplist.each { |op|
        next if not op.bin.kind_of? Integer
        build_opcode_bin_mask(op, mode)
        mj = major_opcode(op.bin, mode)
        if mode == 32 and mj == 5
          (lookaside[mj][sub_opcode(op.bin)] ||= []) << op
        else
          (lookaside[mj] ||= []) << op
        end
      }
      bin_lookaside[mode] = lookaside
    }
    bin_lookaside
  end

  def instruction_size(edata)
    val = major_opcode(edata.decode_imm(:u16, @endianness))
    edata.ptr -= 2
    (val >= 0xC) ? 16 : 32
  end

  def memref_size(di)
    case di.opcode.name
    when 'ldb_s', 'stb_s', 'extb_s', 'sexb_s'; 1
    when 'ldw_s', 'stw_s', 'extw_s', 'sexw_s'; 2
    else 4
    end
  end

  def decode_bin(edata, sz)
    case sz
    when 16; edata.decode_imm(:u16, @endianness)
    when 32
      # wordswap
      val = edata.decode_imm(:u32, :little)
      ((val >> 16) & 0xffff) | ((val & 0xffff) << 16)
    end
  end

  def decode_findopcode(edata)
    di = DecodedInstruction.new(self)

    @instrlength = instruction_size(edata)
    val = decode_bin(edata, @instrlength)
    edata.ptr -= @instrlength/8

    maj = major_opcode(val, @instrlength)
    lookaside = @bin_lookaside[@instrlength][maj]
    lookaside = lookaside[sub_opcode(val)] if @instrlength == 32 and maj == 5

    op = lookaside.select { |opcode|
      if $ARC_DEBUG and (val & opcode.bin_mask) == opcode.bin
        puts "#{opcode.bin_mask.to_s(16)} - #{opcode.bin.to_s(16)} - #{(val & opcode.bin_mask).to_s(16)} -  #{opcode.name} - #{opcode.args}"
      end
      (val & opcode.bin_mask) == opcode.bin
    }

    if op.size == 2 and op.first.name == 'mov' and op.last.name == 'nop'
      op = op.last
    elsif op == nil or op.size != 1
      puts "[> I sense a disturbance in the force <]"
      op.to_a.each { |opcode| puts "#{opcode.name} - #{opcode.args} - #{Expression[opcode.bin]} - #{Expression[opcode.bin_mask]}" }
      puts "current value: #{Expression[val]}"
      puts "current value: 0b#{val.to_s(2)}"
      op = nil
    else
      op = op.first
    end

    di if di.opcode = op
  end

  Reduced_reg = [0, 1, 2, 3, 12, 13, 14, 15]
  def reduced_reg_set(i)
    Reduced_reg[i]
  end

  def decode_instr_op(edata, di)
    before_ptr = edata.ptr
    op = di.opcode
    di.instruction.opname = op.name
    val = decode_bin(edata, @instrlength)

    field_val = lambda { |f|
      r = (val >> @fields_shift[f]) & @fields_mask[f]
      case f

      # 16-bits instruction operands ------------------------------------------"
      when :ca, :cb, :cb2, :cb3, :cc;  r = reduced_reg_set(r)
      when :ch
        r = (((r & 7) << 3) | (r >> 5))
      when :@cbu7, :@cbu6, :@cbu5
        r = r & 0b11111
        r = (f == :@cbu7) ? r << 2 : ( (f == :@cbu6) ? r << 1 : r)
      when :cu5ee; r = r << 2
      when :cdisps13
        r = (Expression.make_signed(r,11) << 2) + ((di.address >> 2) << 2)
      when :cdisps10
        r = (Expression.make_signed(r, 9) << 1) + ((di.address >> 2) << 2)
      when :cdisps8
        r = (Expression.make_signed(r, 7) << 1) + ((di.address >> 2) << 2)
      when :cdisps7
        r = (Expression.make_signed(r, 6) << 1) + ((di.address >> 2) << 2)
      when :cs9, :cs10, :cs11
        r = Expression.make_signed(r, ((f== :cs11 ? 11 : (f == :cs10 ? 10 : 9) )))
        r = (f == :cs11) ? r << 2 : ((f == :cs10) ? r << 1 : r)
      when :@cspu7;
        r = r << 2

      # 32-bits instruction operands ------------------------------------------"
      when :b
        r = (r >> 12) | ((r & 0x7) << 3)
      when :s8e
        r = ((r & 0x1) << 7) | (r >> 2)
        r = (Expression.make_signed(r, 8) << 1) + ((di.address >> 2) << 2)

      when :u6e
        r = (r << 1) + ((di.address >> 2) << 2)
      when :s9
        r = (Expression.make_signed(r, 7) << 1) + ((di.address >> 2) << 2)

      when :s12
        r = (r >> 6) | ((r & 0x3f) << 6)
        r = Expression.make_signed(r, 12)

      when :s12e
        r = (r >> 6) | ((r & 0x3f) << 6)
        r = (Expression.make_signed(r, 12) <<1 ) + ((di.address >> 2) << 2)

      when :s21e
        r = ((r & 0x3ff) << 10) | (r >> 11)
        r = (Expression.make_signed(r, 20) << 1) + ((di.address >> 2) << 2)

      when :s21ee # pc-relative
        r = ((r & 0x3ff) << 9) | (r >> 12)
        r = (Expression.make_signed(r, 19) << 2) + ((di.address >> 2) << 2)

      when :s25e # pc-relative
        r = ((r & 0xf) << 20)  | (((r >> 6) & 0x3ff) << 10) | (r >> 17)
        r = (Expression.make_signed(r, 24) << 1) + ((di.address >> 2) << 2)

      when :s25ee # pc-relative
        r = ((r & 0xf) << 19)  | (((r >> 6) & 0x3ff) << 9) | (r >> 18)
        r = (Expression.make_signed(r, 23) << 2) + ((di.address >> 2) << 2)

      when :@bs9
        r = r >> 3
        s9 = ((r & 1) << 8) | ((r >> 1) & 0xff)
        r = Expression.make_signed(s9, 9)

      when :bext, :cext, :@cext
        if ((r = field_val[(f == :bext) ? :b : :c]) == 0x3E)
          tmp = edata.decode_imm(:u32, :little)
          r = Expression[(tmp >> 16) | ((tmp & 0xffff) << 16)]
        else
          r = GPR.new(r)
        end

      else r
      end
      r
    }

    # decode properties fields
    op.args.each { |a|
      case a
      when :flags15, :flags16
        di.instruction.opname += '.f' if field_val[a] != 0
      when :ccond
        di.instruction.opname += ('.' + @cond_suffix[field_val[a]]) if field_val[a] != 0
      when :delay5, :delay16
        di.instruction.opname += '.d' if field_val[a] != 0
      when :cache5, :cache11, :cache16
        di.instruction.opname +='.di' if field_val[a] != 0
      when :signext6, :signext16
        di.instruction.opname += '.x' if field_val[a] != 0
      when :wb3, :wb9, :wb22
        case field_val[a]
        when 1; di.instruction.opname += ((memref_size(di) == 2) ? '.ab' : '.a')
        when 2; di.instruction.opname += '.ab'
        when 3; di.instruction.opname += '.as'
        end
      when :sz1, :sz7, :sz16, :sz17
        case field_val[a]
        when 1; di.instruction.opname += 'b'
        when 2; di.instruction.opname += 'w'
        end
      else
        di.instruction.args << case a

        # 16-bits instruction operands ------------------------------------------"
        when :cr0; GPR.new 0
        when :ca, :cb, :cb2, :cb3, :cc; GPR.new(field_val[a])
        when :ch
          if ((r = field_val[a]) == 0x3E)
            tmp = edata.decode_imm(:u32, :little)
            Expression[(tmp >> 16) | ((tmp & 0xffff) << 16)]
          else
            GPR.new(r)
          end

        when :@gps9, :@gps10, :@gps11
          imm = (a == :@gps11) ? :cs11 : (a == :@gps10) ? :cs10 : :cs9
          Memref.new(GPR.new(26), Expression[field_val[imm]], memref_size(di))

        when :cu3, :cu5, :cu5ee, :cu6, :cu7, :cu7l, :cu8; Expression[field_val[a]]
        when :cs9, :cs10, :cs11;  Expression[field_val[a]]
        when :cdisps7, :cdisps8, :cdisps10, :cdisps13; Expression[field_val[a]]
        when :@cb; Memref.new(GPR.new(field_val[:cb]), nil, memref_size(di))
        when :@cbu7, :@cbu6, :@cbu5; Memref.new(GPR.new(field_val[:cb]), Expression[field_val[a]], memref_size(di))
        when :@cspu7; Memref.new(GPR.new(28), field_val[a], memref_size(di))
        when :@cbcc; Memref.new(field_val[:cb], field_val[:cc], memref_size(di))

        # 32-bits instruction operands ------------------------------------------"
        when :a, :b
          ((r = field_val[a]) == 0x3E) ? :zero : GPR.new(r)
        when :b2; GPR.new field_val[:b]
        when :c; GPR.new field_val[a]
        when :bext, :cext; field_val[a]
        when :@cext
          target = field_val[a]
          (di.opcode.props[:setip] and target.kind_of? GPR) ? Memref.new(target, nil, memref_size(di)) : target

        when :@bextcext
          tmp = field_val[a]
          #c = tmp & 0x3F
          tmp = tmp >> 6
          b = (tmp >> 12) | ((tmp & 0x7) << 3)
          Memref.new(field_val[:bext],  field_val[:cext], memref_size(di))

        when :u6, :u6e, :s8e, :s9, :s12; Expression[field_val[a]]
        when :s12e, :s21e, :s21ee, :s25e, :s25ee; Expression[field_val[a]]
        when :auxs12; AUX.new field_val[:s12]
        when :@c; Memref.new(GPR.new(field_val[a]),  nil, memref_size(di))
        when :@bcext; Memref.new(field_val[a],  nil, memref_size(di))
        when :@bcext; Memref.new(field_val[:b], field_val[:cext], memref_size(di))
        when :@bs9
          # [b,s9] or [limm] if b = 0x3E
          base = field_val[:bext]
          Memref.new(base, (base.kind_of? GPR) ? Expression[field_val[a]] : nil, memref_size(di))

        # common instruction operands ------------------------------------------"
        when :zero; Expression[0]
        when :gp; GPR.new(26)
        when :sp, :sp2; GPR.new(28)
        when :blink; GPR.new(31)
        when :@ilink1; Memref.new(GPR.new(29), nil, memref_size(di))
        when :@ilink2; Memref.new(GPR.new(30), nil, memref_size(di))
        when :@blink;  Memref.new(GPR.new(31), nil, memref_size(di))

        else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
        end
      end
    }

    di.bin_length += edata.ptr - before_ptr

    return if edata.ptr > edata.virtsize

    di
  end

  def disassembler_default_func
    df = DecodedFunction.new
    df.backtrace_binding = {}
    15.times { |i|
      df.backtrace_binding["r#{i}".to_sym] = Expression::Unknown
    }
    df.backtracked_for = []
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

  REG_SYMS = [:r26, :r27, :r28, :r29, :r30, :r31, :r60]
  def register_symbols
    REG_SYMS
  end

  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end

  def opshift(op)
    op[/\d/].to_i
  end

  def with_res(arg)
    arg != :zero
  end

  def init_backtrace_binding
    sp = :r28
    blink = :r31

    @backtrace_binding ||= {}

    mask = lambda { |sz| (1 << sz)-1 }  # 32bits => 0xffff_ffff

    opcode_list.each{|mode, oplist|
      oplist.map { |ol| ol.name }.uniq.each { |op|
        binding = case op
            when /^add/, /^sub/
              lambda { |di, a0, a1, a2|
                if (shift = opshift(op)) == 0
                  { a0 => Expression[[a1, :+, a2], :&, mask[32]] }
                else
                  { a0 => Expression[[a1, :+, [a2, :<<, shift]], :&, mask[32]] }
                end
              }
            when /^and/
              lambda { |di, a0, a1, a2| { a0 => Expression[a1, :&, a2] } }
            when /^asl/
              lambda { |di, *a| { a[0] => Expression[[a[1], :<<, (a[2] ? a[2]:1)], :&, mask[32]] } }
            when /^bxor/
              lambda { |di, a0, a1, a2| { a0 => Expression[a1, :^, [1, :<<, a2]] }}
            when /^bclr/; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :&, Expression[mask[32], :^, Expression[1, :<<, a2]]] } }
            when /^bset/; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :|, Expression[1, :<<, a2]] } }
            when /^jl/; lambda { |di, a0| { blink => Expression[di.next_addr] } }
            when 'bl', 'bl_s', /^bl\./
              # FIXME handle delay slot
              # "This address is taken either from the first instruction following the branch (current PC) or the
              # instruction after that (next PC) according to the delay slot mode (.d)."
              lambda { |di, a0| { blink => Expression[di.next_addr] } }
            when /^mov/, /^lr/, /^ld/; lambda { |di, a0, a1| { a0 => a1 } }
            when /^neg/; lambda { |di, a0, a1| { a0 => Expression[[0, :-, a1], :&, mask[32]] } }
            when /^not/; lambda { |di, a0, a1| { a0 => Expression[[:~, a1], :&, mask[32]] } }
            when /^or/; lambda { |di, a0, a1, a2| { a0 => Expression[a1, :|, a2] } }
            when /^st/, /^sr/;  lambda { |di, a0, a1| { a1 => a0 } }
            when /^ex/; lambda { |di, a0, a1| { a1 => a0 , a0 => a1 } }
            when 'push_s'
              lambda { |di, a0| {
                sp => Expression[sp, :-, 4],
                Indirection[sp, @size/8, di.address] => Expression[a0]
              } }
            when 'pop_s'
              lambda { |di, a0| {
                a0 => Indirection[sp, @size/8, di.address],
                sp => Expression[sp, :+, 4]
              } }
            end
        @backtrace_binding[op] ||= binding if binding
      }
    }

    @backtrace_binding
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when GPR; arg.symbolic
      when Memref; arg.symbolic(di.address)
      else arg
      end
    }

    if binding = backtrace_binding[di.opcode.basename]
      binding[di, *a]
    else
      puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
      { :incomplete_binding => Expression[1] }
    end
  end

  def get_xrefs_x(dasm, di)
    return [] if not di.opcode.props[:setip]

    arg = case di.opcode.name
          when 'b', 'b_s', /^j/, /^bl/, /^br/, 'lp'
            expr = di.instruction.args.last
            expr.kind_of?(Memref) ? expr.base : expr
          else di.instruction.args.last
          end

    [Expression[(arg.kind_of?(Reg) ? arg.symbolic : arg)]]
  end

  def backtrace_is_function_return(expr, di=nil)
    Expression[expr].reduce == Expression[register_symbols[5]]
  end

  def delay_slot(di=nil)
    return 0 if (not di) or (not di.opcode.props[:setip])
    return 1 if di.opcode.props[:delay_slot]
    (di.instruction.opname =~ /\.d/) ? 0 : 1
  end
end
end
