#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/arm/opcodes'
require 'metasm/parse'

module Metasm
class ARM
	def parse_init(program)
		program.parse <<EOI
li macro reg, imm
	lui reg, imm >> 16
	ori reg, reg, imm & 0ffffh
endm

EOI
	end

	def parse_arg_valid?(op, sym, arg)
		# special case for lw reg, imm32(reg) ? (pseudo-instr, need to convert to 'lui t0, up imm32  ori t0 down imm32  add t0, reg  lw reg, 0(t0)
		case sym
		when :rs, :rt, :rd:   arg.class == Reg
		when :sa, :i16, :i26: arg.kind_of? Expression
		when :rs_i16:         arg.class == Memref
		when :ft:             arg.class == FpReg
		end
	end

        def parse_argument(pgm)
		if Reg.s_to_i[pgm.nexttok]
			arg = Reg.new Reg.s_to_i[pgm.readtok]
		elsif FpReg.s_to_i[pgm.nexttok]
			arg = FpReg.new FpReg.s_to_i[pgm.readtok]
		else
			arg = Expression.parse pgm
			if arg and pgm.nexttok == :'('
				pgm.readtok
				raise pgm, "Invalid base #{nexttok}" unless Reg.s_to_i[pgm.nexttok]
				base = Reg.new Reg.s_to_i[pgm.readtok]
				raise pgm, "Invalid memory reference, ')' expected" if pgm.readtok != :')'
				arg = Memref.new base, arg
			end
		end
		arg
	end
end
end
