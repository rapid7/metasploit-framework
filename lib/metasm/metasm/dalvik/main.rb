#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class Dalvik < CPU
	class Reg
		attr_accessor :i
		def initialize(i)
			@i = i
		end

		def symbolic
			"r#@i".to_sym
		end

		def to_s
			"r#@i"
		end
	end

	def initialize(endianness = :little)
		super()
		@endianness = endianness
		@size = 32
	end

	def init_opcode_list
		init_latest
		@opcode_list
	end
end
end

