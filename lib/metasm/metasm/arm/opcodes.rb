#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2008 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/arm/main'

module Metasm
class ARM
	private
	def addop(name, bin, *args)
		o = Opcode.new(self, name)

		o.bin = bin
		o.args.concat(args & @fields_mask.keys)
		(args & @valid_props).each { |p| o.props[p] = true }

		(args & @fields_mask.keys).each { |f|
			o.fields[f] = [@fields_mask[f], @fields_shift[f]]
		}

		@opcode_list << o
	end

	def init_arm
		@opcode_list = []
		@fields_mask.update :rs => 0x1f, :rt => 0x1f, :rd => 0x1f, :sa => 0x1f,
			:i16 => 0xffff, :i26 => 0x3ffffff, :rs_i16 => 0x3e0ffff, :it => 0x1f,
			:ft => 0x1f, :i32 => 0
		@fields_shift.update :rs => 21, :rt => 16, :rd => 11, :sa => 6,
			:i16 => 0, :i26 => 0, :rs_i16 => 0, :it => 16,
			:ft => 16, :i32 => 0

		#addop 'j',    0b000010 << 26, :i26, :setip, :stopexec	# sets the program counter to (i26 << 2) | ((pc+4) & 0xfc000000) ie i26*4 in the 256M-aligned section containing the instruction in the delay slot
		#addop 'jal',  0b000011 << 26, :i26, :setip, :stopexec	# same thing, saves return addr in r31

		#addop 'mov',  0b001000 << 26, :rt, :rs			# rt <- rs+0
		#addop 'addi', 0b001000 << 26, :rt, :rs, :i16		# add		rt <- rs+i
	end
	alias init_latest init_arm
end
end
