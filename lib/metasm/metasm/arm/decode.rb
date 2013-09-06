#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/arm/opcodes'
require 'metasm/decode'

module Metasm
class ARM
  # create the bin_mask for a given opcode
  def build_opcode_bin_mask(op)
    # bit = 0 if can be mutated by an field value, 1 if fixed by opcode
    op.bin_mask = 0
    op.fields.each { |k, (m, s)|
      op.bin_mask |= m << s
    }
    op.bin_mask = 0xffffffff ^ op.bin_mask
  end

  # create the lookaside hash from the first byte of the opcode
  def build_bin_lookaside
    lookaside = Array.new(256) { [] }

    opcode_list.each { |op|
      build_opcode_bin_mask op

      b   = (op.bin >> 20) & 0xff
      msk = (op.bin_mask >> 20) & 0xff
      b &= msk

      for i in b..(b | (255^msk))
        lookaside[i] << op if i & msk == b
      end
    }

    lookaside
  end

  def decode_findopcode(edata)
    return if edata.ptr >= edata.data.length
    di = DecodedInstruction.new(self)
    val = edata.decode_imm(:u32, @endianness)
    di.instance_variable_set('@raw', val)
    di if di.opcode = @bin_lookaside[(val >> 20) & 0xff].find { |op|
      (not op.props[:cond] or
       ((val >> @fields_shift[:cond]) & @fields_mask[:cond]) != 0xf) and
      (op.bin & op.bin_mask) == (val & op.bin_mask)
    }
  end

  def disassembler_default_func
    df = DecodedFunction.new
    df
  end

  def decode_instr_op(edata, di)
    op = di.opcode
    di.instruction.opname = op.name
    val = di.instance_variable_get('@raw')
    
    field_val = lambda { |f|
      r = (val >> @fields_shift[f]) & @fields_mask[f]
      case f
      when :i16; Expression.make_signed(r, 16)
      when :i24; Expression.make_signed(r, 24)
      when :i8_12; ((r >> 4) & 0xf0) | (r & 0xf)
      when :stype; [:lsl, :lsr, :asr, :ror][r]
      when :u; [:-, :+][r]
      else r
      end
    }

    if op.props[:cond]
      cd = %w[eq ne cs cc mi pl vs vc hi ls ge lt gt le al][field_val[:cond]]
      if cd != 'al'
        di.opcode = di.opcode.dup
        di.instruction.opname = di.opcode.name.dup
        di.instruction.opname[(op.props[:cond_name_off] || di.opcode.name.length), 0] = cd
        if di.opcode.props[:stopexec]
          di.opcode.props = di.opcode.props.dup
          di.opcode.props.delete :stopexec
        end
      end
    end

    op.args.each { |a|
      di.instruction.args << case a
      when :rd, :rn, :rm; Reg.new field_val[a]
      when :rm_rs; Reg.new field_val[:rm], field_val[:stype], Reg.new(field_val[:rs])
      when :rm_is; Reg.new field_val[:rm], field_val[:stype], field_val[:shifti]*2
      when :i24; Expression[field_val[a] << 2]
      when :i8_r
        i = field_val[:i8]
        r = field_val[:rotate]*2
        Expression[((i >> r) | (i << (32-r))) & 0xffff_ffff]
      when :mem_rn_rm, :mem_rn_i8_12, :mem_rn_rms, :mem_rn_i12
        b = Reg.new(field_val[:rn])
        o = case a
        when :mem_rn_rm; Reg.new(field_val[:rm])
        when :mem_rn_i8_12; field_val[:i8_12]
        when :mem_rn_rms; Reg.new(field_val[:rm], field_val[:stype], field_val[:shifti]*2)
        when :mem_rn_i12; field_val[:i12]
        end
        Memref.new(b, o, field_val[:u], op.props[:baseincr])
      when :reglist
        di.instruction.args.last.updated = true if op.props[:baseincr]
        msk = field_val[a]
        l = RegList.new((0..15).map { |i| Reg.new(i) if (msk & (1 << i)) > 0 }.compact)
        l.usermoderegs = true if op.props[:usermoderegs]
        l
      else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
      end
    }

    di.bin_length = 4
    di
  end

  def decode_instr_interpret(di, addr)
    if di.opcode.args.include? :i24
      di.instruction.args[-1] = Expression[di.instruction.args[-1] + addr + 8]
    end
    di
  end

  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end
 
  def init_backtrace_binding
    @backtrace_binding ||= {}
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when Reg; arg.symbolic
      when Memref; arg.symbolic(di.address)
      else arg
      end
    }
  
    if binding = backtrace_binding[di.opcode.name]
      bd = binding[di, *a]
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
  
  def get_xrefs_x(dasm, di)
    if di.opcode.props[:setip]
      [di.instruction.args.last]
    else
      # TODO ldr pc, ..
      []
    end
  end
end
end
