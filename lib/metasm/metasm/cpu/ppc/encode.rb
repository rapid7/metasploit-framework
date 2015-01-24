#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/ppc/opcodes'
require 'metasm/encode'

module Metasm
class PowerPC
  private
  def encode_instr_op(exe, instr, op)
    base = op.bin
    set_field = lambda { |f, v|
      base |= (v & @fields_mask[f]) << @fields_shift[f]
    }

    val, mask, shift = 0, 0, 0

# TODO
    # convert label name for jmp/call/loop to relative offset
    if op.props[:setip] and op.name[0] != ?t and instr.args.last.kind_of? Expression
      postlabel = exe.new_label('jmp_offset')
      instr = instr.dup
      instr.args[-1] = Expression[[instr.args[-1], :-, postlabel], :>>, 2]
      postdata = EncodedData.new '', :export => {postlabel => 0}
    else
      postdata = ''
    end

    op.args.zip(instr.args).each { |sym, arg|
      case sym
      when :rs, :rt, :rd, :ba, :bf, :bfa, :bt
        set_field[sym, arg.i]
      when :ft
        set_field[sym, arg.i]
      when :rs_i16
        set_field[:rs, arg.base.i]
        val, mask, shift = arg.offset, @fields_mask[:i16], @fields_shift[:i16]
      when :sa, :i16, :i20
        val, mask, shift = arg, @fields_mask[sym], @fields_shift[sym]
      when :i26
        val, mask, shift = Expression[arg, :>>, 2], @fields_mask[sym], @fields_shift[sym]
      end
    }

    Expression[base, :+, [[val, :&, mask], :<<, shift]].encode(:u32, @endianness) << postdata
  end
end
end
