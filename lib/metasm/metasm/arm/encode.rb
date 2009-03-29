#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2008 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/arm/opcodes'
require 'metasm/encode'

module Metasm
class ARM
	private
	def encode_instr_op(section, instr, op)
		base = op.bin
		set_field = lambda { |f, v|
			base |= (v & @fields_mask[f]) << @fields_shift[f]
		}

		val, mask, shift = 0, 0, 0

		op.args.zip(instr.args).each { |sym, arg|
		}
	end
end
end
