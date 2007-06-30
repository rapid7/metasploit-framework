#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class Ia32 < CPU

	# some ruby magic
	class Argument
		@simple_list = []
		@double_list = []
		class << self
			# for Argument
			attr_reader :simple_list, :double_list
			# for subclasses
			attr_reader :i_to_s, :s_to_i
		end

		private
		def self.simple_map(a)
			Argument.simple_list << self

			@i_to_s = Hash[*a.flatten]
			@s_to_i = @i_to_s.invert
			
			class_eval {
				attr_accessor :val
				def initialize(v)
					raise Exception, "invalid #{self.class} #{v}" unless self.class.i_to_s[v]
					@val = v
				end
			}
		end

		def self.double_map(h)
			Argument.double_list << self

			@i_to_s = h
			@s_to_i = {} ; h.each { |sz, hh| hh.each_with_index { |r, i| @s_to_i[r] = [i, sz] } }

			class_eval {
				attr_accessor :val, :sz
				def initialize(v, sz)
					raise Exception, "invalid #{self.class} #{sz}/#{v}" unless self.class.i_to_s[sz] and self.class.i_to_s[sz][v]
					@val = v
					@sz = sz
				end
			}
		end

	end
	

	class SegReg < Argument
		simple_map((0..5).zip(%w(es cs ss ds fs gs)))
	end
	
	class DbgReg < Argument
		simple_map [0, 1, 2, 3, 6, 7].map { |i| [i, "dr#{i}"] }
	end
	
	class CtrlReg < Argument
		simple_map [0, 2, 3, 4].map { |i| [i, "cr#{i}"] }
	end
	
	class FpReg < Argument
		simple_map((0..7).map { |i| [i, "ST(#{i})"] } << [nil, 'ST'])
	end
	
	class SimdReg < Argument
		double_map  64 => (0..7).map { |n| "mm#{n}" },
			   128 => (0..7).map { |n| "xmm#{n}" }
	end
	
	class Reg < Argument
		double_map  8 => %w{ al  cl  dl  bl  ah  ch  dh  bh},
			   16 => %w{ ax  cx  dx  bx  sp  bp  si  di},
			   32 => %w{eax ecx edx ebx esp ebp esi edi}
			  #64 => %w{rax rcx rdx rbx rsp rbp rsi rdi}
	end
	
	class Farptr < Argument
		attr_reader :seg, :addr
		def initialize(seg, addr)
			@seg, @addr = seg, addr
		end
	end

	class ModRM < Argument
		Sum = {
		    16 => {
			0 => [ [3, 6], [3, 7], [5, 6], [5, 7], [6], [7], [:i16], [3] ],
			1 => [ [3, 6, :i8 ], [3, 7, :i8 ], [5, 6, :i8 ], [5, 7, :i8 ], [6, :i8 ], [7, :i8 ], [5, :i8 ], [3, :i8 ] ],
			2 => [ [3, 6, :i16], [3, 7, :i16], [5, 6, :i16], [5, 7, :i16], [6, :i16], [7, :i16], [5, :i16], [3, :i16] ]
		    },
		    32 => {
			0 => [ [0], [1], [2], [3], [:sib], [:i32], [6], [7] ],
			1 => [ [0, :i8 ], [1, :i8 ], [2, :i8 ], [3, :i8 ], [:sib, :i8 ], [5, :i8 ], [6, :i8 ], [7, :i8 ] ],
			2 => [ [0, :i32], [1, :i32], [2, :i32], [3, :i32], [:sib, :i32], [5, :i32], [6, :i32], [7, :i32] ]
		    }
		}
	
		
		attr_accessor :adsz, :sz
		attr_accessor :seg
		attr_accessor :s, :i, :b, :imm
	
		def initialize(adsz, sz, s, i, b, imm, seg = nil)
			@adsz, @sz, @s, @i, @b, @imm, @seg = adsz, sz, s, i, b, imm, seg
		end
	end

	def initialize(family = :sse3, mode = 32)
		super()
		@endianness = :little
		@size = mode
		send "init_#{family}"
	end
end

end
