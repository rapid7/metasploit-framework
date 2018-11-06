#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm64/opcodes'
require 'metasm/encode'

module Metasm
class ARM64
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

		op.args.zip(instr.args).each { |sym, arg|
			case sym
			when :rd, :rs, :rn, :rm, :rt
				if arg.sz == 32
					set_field[:sf, 0]
				elsif op.field[:sf]
					set_field[:sf, 1]
				end
			       	set_field[sym, arg.i]
			end
		}

		Expression[base].encode(:u32, @endianness)
	end
end
end
