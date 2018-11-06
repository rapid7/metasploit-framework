#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/arm64/opcodes'
require 'metasm/parse'

module Metasm
class ARM64
	def parse_arg_valid?(op, sym, arg)
		false
	end

	def parse_argument(lexer)
		raise lexer, 'fu'
	end
end
end
