#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2015-2016 Google
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class MCS51 < CPU

	class Reg
		I_TO_S  = { 0x4 => 'A',
		            0x5 => 'B',
		            0x8 => 'R0',
		            0x9 => 'R1',
		            0xA => 'R2',
		            0xB => 'R3',
		            0xC => 'R4',
		            0xD => 'R5',
		            0xE => 'R6',
		            0xF => 'R7'
		}

		S_TO_I = { 'A' => 0x4,
		           'B' => 0x5 }

		def initialize(i)
			@i = i
		end

		def to_s
			I_TO_S[@i]
		end

		def self.from_str(s)
			new(S_TO_I[s])
		end

	end

	class Immediate
		def initialize(value)
			@value = value
		end

		def to_s
			"#" + @value.to_s
		end
	end

	class Memref
		attr_accessor :base, :offset
		def initialize(base, offset)
			@base = base
			@offset = offset
		end

		def to_s
			@base ? "@" + @base.to_s : @offset.to_s
		end
	end

	def initialize
		super()
		@endianness = :big
		@size = 8
	end

	def init_opcode_list
		init_mcs51
		@opcode_list
	end
end
end

