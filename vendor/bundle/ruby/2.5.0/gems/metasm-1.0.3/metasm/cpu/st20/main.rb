#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class ST20 < CPU
	def initialize(size=32)
		super()
		@endianness = :little
		@size = size
		init_opcodes
	end

	def register_symbols
		[:a, :b, :c]
	end

	def render_instruction(i)
		r = []
		r << i.opname
		if not i.args.empty?
			r << ' '
			i.args.each { |a_| r << a_ << ', ' }
			r.pop
		end
		r
	end
end

class TransPuter < ST20
end
end

