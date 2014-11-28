#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/mips/opcodes'
require 'metasm/encode'

module Metasm
class MIPS
  private
  def encode_instr_op(exe, instr, op)
    base = op.bin
    set_field = lambda { |f, v|
      base |= (v & @fields_mask[f]) << @fields_shift[f]
    }

    val, mask, shift = 0, 0, 0

    # convert label name for jmp/call/loop to relative offset
    if op.props[:setip] and op.name[0] != ?t and instr.args.last.kind_of? Expression
      postlabel = exe.new_label('jmp_offset')
      instr = instr.dup
      if op.args.include? :i26
        pl = Expression[postlabel, :&, 0xfc00_0000]
      else
        pl = postlabel
      end
      instr.args[-1] = Expression[[instr.args[-1], :-, pl], :>>, 2]
      postdata = EncodedData.new '', :export => {postlabel => 0}
    else
      postdata = ''
    end

    op.args.zip(instr.args).each { |sym, arg|
      case sym
      when :rs, :rt, :rd, :ft
        set_field[sym, arg.i]
      when :rs_i16
        set_field[:rs, arg.base.i]
        val, mask, shift = arg.offset, @fields_mask[:i16], @fields_shift[:i16]
      when :sa, :i16, :i20, :i26, :it, :msbd, :sel, :idb
        val, mask, shift = arg, @fields_mask[sym], @fields_shift[sym]
        val = Expression[val, :-, 1] if sym == :msbd
      end
    }

    Expression[base, :|, [[val, :&, mask], :<<, shift]].encode(:u32, @endianness) << postdata
  end
end
end
