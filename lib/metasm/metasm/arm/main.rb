#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2008 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class ARM < CPU
	class Reg
		class << self
			attr_accessor :s_to_i, :i_to_s
		end
		@i_to_s = %w[r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 sl fp ip sp lr pc]
		@s_to_i = { 'wr' => 7, 'sb' => 9, 'sl' => 10, 'fp' => 11, 'ip' => 12, 'sp' => 13, 'lr' => 14, 'pc' => 15 }
		15.times { |i| @s_to_i["r#{i}"] = i }
		4.times { |i| @s_to_i["a#{i+1}"] = i }
		8.times { |i| @s_to_i["v#{i+1}"] = i+4 }

		attr_accessor :i
		def initialize(i)
			@i = i
		end
	end

#	class Memref
#		attr_accessor :base, :offset
#		def initialize(base, offset)
#			@base, @offset = base, offset
#		end
#	end

	def initialize(endianness = :little)
		super()
		@endianness = endianness
		@size = 32
		init_latest
	end
end

class ARM_THUMB < ARM
end
end

