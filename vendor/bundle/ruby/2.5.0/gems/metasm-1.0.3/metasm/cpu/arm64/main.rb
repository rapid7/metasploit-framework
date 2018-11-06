#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class ARM64 < CPU
	class Reg
		class << self
			attr_accessor :s_to_i, :i_to_s
		end
		@i_to_s = { 32 => (0..30).inject({}) { |h, i| h.update i => "w#{i}" }.merge(31 => 'wsp', 32 => 'wzr'),
			    64 => (0..30).inject({}) { |h, i| h.update i => "x#{i}" }.merge(31 => 'sp', 32 => 'xzr', 33 => 'pc')
	       	}

		attr_accessor :i, :sz
		def initialize(i, sz)
			@i = i
			@sz = sz
		end

		Sym = @i_to_s[64].inject({}) { |h, (k, v)| h.update k => v.to_sym }

		def symbolic
			if @sz == 64
				Sym[@i]
			else
				Expression[Sym[@i], :&, 0xffffffff]
			end
		end
	end

	class RegShift
		attr_accessor :reg, :mode, :shift
		def initialize(reg, mode, shift)
			@reg = reg
			@mode = mode
			@shift = shift
		end

		def symbolic
			sym = @reg.symbolic
			if shift != 0
				case @mode
				when :lsl; Expression[sym, :<<, shift]
				when :lsr; Expression[sym, :>>, shift]
				when :asr; Expression[sym, :>>, shift]	# signextend
				end
			end
			sym
		end
	end

	class RegCC
		attr_accessor :cc
		def initialize(cc)
			@cc = cc
		end
		def symbolic
			0
		end
	end

	class Memref
		attr_accessor :base, :index, :scale, :offset, :sz, :incr
		def initialize(base, index, scale, offset, sz, incr=nil)
			@base, @index, @scale, @offset, @sz, @incr = base, index, scale, offset, sz, incr
		end

		def symbolic(orig=nil)
			o = Expression[@base.symbolic]
			if @index
				si = @index.symbolic
				si = Expression[@scale, :*, @index] if @scale != 1
				o = Expression[o, :+, si]
			end
			o = Expression[o, :+, @offset] if @offset and @incr != :post
			Indirection[o.reduce, @sz, orig]
		end
	end

	class RegList
		attr_accessor :list

		def initialize(l=[])
			@list = l
		end
	end

	def initialize(endianness = :little)
		super()
		@endianness = endianness
		@size = 64
	end

	def init_opcode_list
		init_latest
		@opcode_list
	end
end
end

