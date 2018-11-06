#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm64/opcodes'

module Metasm
class ARM64
	def dbg_register_pc
		@dbg_register_pc ||= :pc
	end
	def dbg_register_flags
		@dbg_register_flags ||= :flags
	end

	def dbg_register_list
		@dbg_register_list ||= Reg::Sym.sort.transpose[1] - [:xzr]
	end

	def dbg_flag_list
		@dbg_flag_list ||= []
	end

	def dbg_register_size
		@dbg_register_size ||= Hash.new(64)
	end

	def dbg_need_stepover(dbg, addr, di)
		di and di.opcode.props[:saveip]
	end

	def dbg_end_stepout(dbg, addr, di)
		di and di.opcode.name == 'foobar'
	end
end
end
