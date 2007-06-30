#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/opcodes'
require 'metasm/render'

# XXX move context in another file ?
module Metasm
class Ia32
	class Argument
		include Renderable

		@simple_list.each { |c| c.class_eval {
			def render ; [self.class.i_to_s[@val]] end
		} }
		@double_list.each { |c| c.class_eval {
			def render ; [self.class.i_to_s[@sz][@val]] end
			def context ; {'set sz' => proc { |s| @sz = s }} end
		} }
	end

	class Farptr
		def render
			[@seg, ':', @addr]
		end
	end

	class ModRM
		def qualifier(sz)
			{
			 8 => 'byte',
			16 => 'word',
			32 => 'dword',
			64 => 'qword'
			}.fetch(sz) { |k| "_#{sz}bits" }
		end

		def render
			r = []
			# is 'dword ptr' needed ?
#			if not instr or not instr.args.grep(Reg).find {|a| a.sz == @sz}
			r << ( qualifier(@sz) << ' ptr ' )
#			end
			r << @seg << ':' if @seg

			e = nil
			e = Expression[e, :+, (@s == 1 ? @i : [@s, :*, @i])] if @s
			e = Expression[e, :+, @b] if @b
			e = Expression[e, :+, @imm] if @imm
			r << '[' << e << ']'
		end

		def context
			return @direct.context if @direct

			{'set targetsz' => proc {|s| @sz = s},
			 'set seg' => proc {|s| @seg = Seg.new s}
			}
		end
	end

	def render_instruction(i)
		r = []
		r << 'lock ' if i.prefix[:lock]
		r << i.prefix[:rep] << ' ' if i.prefix[:rep]
		r << i.opname
		i.args.each { |a|
			r << (r.last == i.opname ? ' ' : ', ') << a
		}
		r
	end

	def instruction_context(i)
		# XXX
		h = {}
		op = opcode_list_byname[i.opname].first
		if i.prefix[:rep]
			h['toogle repz'] = proc { i.prefix[:rep] = {'repnz' => 'repz', 'repz' => 'repnz'}[i.prefix[:rep]] } if op.props[:stropz]
			h['rm rep']      = proc { i.prefix.delete :rep }
		else
			h['set rep']     = proc { i.prefix[:rep] = 'rep'  } if op.props[:strop]
			h['set rep']     = proc { i.prefix[:rep] = 'repz' } if op.props[:stropz]
		end
		if i.args.find { |a| a.kind_of? ModRM and a.seg }
			h['rm seg'] = proc { i.args.find { |a| a.kind_of? ModRM and a.seg }.seg = nil }
		end
		h['toggle lock'] = proc { i.prefix[:lock] = !i.prefix[:lock] }
		h
	end
end
end
