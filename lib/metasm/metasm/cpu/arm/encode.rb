#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm/opcodes'
require 'metasm/encode'

module Metasm
class ARM
  def encode_instr_op(program, instr, op)
    base = op.bin
    set_field = lambda { |f, v|
      v = v.reduce if v.kind_of?(Expression)
      case f
      when :i8_12
        base = Expression[base, :|, [[v, :&, 0xf], :|, [[v, :<<, 4], :&, 0xf00]]]
        next
      when :stype; v = [:lsl, :lsr, :asr, :ror].index(v)
      when :u; v = [:-, :+].index(v)
      end
      base = Expression[base, :|, [[v, :&, @fields_mask[f]], :<<, @fields_shift[f]]]
    }

    val, mask, shift = 0, 0, 0

    if op.props[:cond]
      coff = op.props[:cond_name_off] || op.name.length
      cd = instr.opname[coff, 2]
      cdi = %w[eq ne cs cc mi pl vs vc hi ls ge lt gt le al].index(cd) || 14	# default = al
      set_field[:cond, cdi]
    end

    op.args.zip(instr.args).each { |sym, arg|
      case sym
      when :rd, :rs, :rn, :rm; set_field[sym, arg.i]
      when :rm_rs
        set_field[:rm, arg.i]
        set_field[:stype, arg.stype]
        set_field[:rs, arg.shift.i]
      when :rm_is
        set_field[:rm, arg.i]
        set_field[:stype, arg.stype]
        set_field[:shifti, arg.shift]
      when :mem_rn_rm, :mem_rn_rms, :mem_rn_i8_12, :mem_rn_i12
        set_field[:rn, arg.base.i]
        case sym
        when :mem_rn_rm
          set_field[:rm, arg.offset.i]
        when :mem_rn_rms
          set_field[:rm, arg.offset.i]
          set_field[:stype, arg.offset.stype]
          set_field[:rs, arg.offset.shift.i]
        when :mem_rn_i8_12
          set_field[:i8_12, arg.offset]
        when :mem_rn_i12
          set_field[:i12, arg.offset]
        end
        # TODO set_field[:u] etc
      when :reglist
        set_field[sym, arg.list.inject(0) { |rl, r| rl | (1 << r.i) }]
      when :i8_r
        b = arg.reduce & 0xffffffff
        r = (0..15).find {
          next true if b < 0x100
          b = ((b << 2) & 0xffff_ffff) | ((b >> 30) & 3)
          false
        }
        raise EncodeError, "Invalid constant" if not r
        set_field[:i8, b]
        set_field[:rotate, r]
      when :i12, :i24
        val, mask, shift = arg, @fields_mask[sym], @fields_shift[sym]
      end
    }

    if op.args[-1] == :i24
      # convert label name for branch to relative offset
      label = program.new_label('l_'+op.name)
      target = val
      target = target.rexpr if target.kind_of?(Expression) and target.op == :+ and not target.lexpr
      val = Expression[[target, :-, [label, :+, 8]], :>>, 2]

      EncodedData.new('', :export => { label => 0 }) <<
      Expression[base, :|, [[val, :<<, shift], :&, mask]].encode(:u32, @endianness)
    else
      Expression[base, :|, [[val, :<<, shift], :&, mask]].encode(:u32, @endianness)
    end
  end
end
end
