#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/render'
require 'metasm/cpu/arm64/opcodes'

module Metasm
class ARM64
	class Reg
		include Renderable
		def render
			[self.class.i_to_s[@sz][@i]]
		end
	end

	class RegShift
		include Renderable
		def render
			case @mode
			when :lsl, :lsr, :asr
				if shift == 0
					[@reg]
				else
					case @mode
					when :lsl; [@reg, ' LSL ', Expression[shift]]
					when :lsr; [@reg, ' LSR ', Expression[shift]]
					when :asr; [@reg, ' ASR ', Expression[shift]]
					end
				end
			else
				sh = []
				sh << ' LSL ' << Expression[shift] if shift != 0
				[ @mode.to_s, '( ', @reg, ' )', *sh ]
			end
		end
	end

	class RegCC
		include Renderable
		def render
			[@cc]
		end
	end

	class Memref
		include Renderable
		def render
			o = Expression[@base]
			if @index
				i = @index
				i = Expression[@scale, :*, @index] if @scale != 1
				o = Expression[o, :+, i]
			end
			case @incr
			when nil
				o = Expression[o, :+, @offset] if @offset and @offset != Expression[0]
				['[', o, ']']
			when :pre
				o = Expression[o, :+, @offset]
				['[', o, ']!']
			when :post
				['[', o, '], ', @offset]
			end
		end
	end

	class RegList
		include Renderable
		def render
			r = ['{']
			@list.each { |l| r << l << ', ' }
			r[-1] = '}'
			r << '^' if usermoderegs
			r
		end
	end

	def gui_hilight_word_regexp_init
		ret = {}
		(0..30).each { |i|
			ret["w#{i}"] = ret["x#{i}"] = "[wx]#{i}"
		}
		ret["sp"] = ret["wsp"] = "w?sp"
		ret["zr"] = ret["wzr"] = "w?zr"
		ret
	end

	def gui_hilight_word_regexp(word)
		@gui_hilight_word_hash ||= gui_hilight_word_regexp_init
		@gui_hilight_word_hash[word] or super(word)
	end
end
end
