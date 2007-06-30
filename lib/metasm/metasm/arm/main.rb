#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class ARM < CPU
	class Reg
		class << self
			attr_reader :s_to_i
		end
		@s_to_i = { 'sp' => 13, 'lr' => 14, 'pc' => 15 }
		(0..15).each { |i| @s_to_i["r#{i}"] = @s_to_i["$r#{i}"] = i }

		attr_reader :i
		def initialize(i)
			@i = i
		end
	end

#	class Memref
#		attr_reader :base, :offset
#		def initialize(base, offset)
#			@base, @offset = base, offset
#		end
#	end

	def initialize(endianness = :little)
		super()
		@endianness = endianness
		@size = 32
		init
	end
end
end

