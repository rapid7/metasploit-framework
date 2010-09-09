#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/pic16c/opcodes'
require 'metasm/decode'

module Metasm
class Pic16c
	def build_opcode_bin_mask(op)
		# bit = 0 if can be mutated by an field value, 1 if fixed by opcode
		op.bin_mask = Array.new(op.bin.length, 0)
		op.fields.each { |f, (oct, off)|
			op.bin_mask[oct] |= (@fields_mask[f] << off)
		}
		op.bin_mask.map! { |v| 255 ^ v }
	end
	
	def build_bin_lookaside
		# sets up a hash byte value => list of opcodes that may match
		# opcode.bin_mask is built here
		lookaside = Array.new(256) { [] }
		@opcode_list.each { |op|
			
			build_opcode_bin_mask op
			
			b   = op.bin[0]
			msk = op.bin_mask[0]
			
			
			for i in b..(b | (255^msk))
				ext if i & msk != b & msk
				
				lookaside[i] << op
			end
		}
		lookaside
	end
end
end
