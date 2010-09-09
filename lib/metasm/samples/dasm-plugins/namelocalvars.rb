#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: replace instances of [ebp-42] with [ebp+var_42] for the current function
# (x86 only)
def namelocalvars(addr)
	vars = []
	each_function_block(addr) { |a|
		decoded[a].block.list.each { |di|
			di.instruction.args.grep(Ia32::ModRM).each { |mrm|
				next if mrm.s or not mrm.b or mrm.b.symbolic != :ebp
				next if not i = mrm.imm or not i = i.reduce or not i.kind_of? Integer
				# after our substitution get_bt_bind will return invalid data
				# XXX probably breaks decompilation
				di.backtrace_binding ||= cpu.get_backtrace_binding(di)
				n = i > 0 ? "arg_#{i.to_s(16)}" : "var_#{(-i).to_s(16)}"
				mrm.imm = Expression[n]
				vars << n
			}
		}
	}
	vars.uniq.sort_by { |n| [n[0, 4], n[4..-1].to_i(16)] }
end

if gui
	gui.keyboard_callback[?L] = lambda {
		puts namelocalvars(gui.curaddr).join(', ')
		gui.gui_update
		true
	}
	gui.keyboard_callback[?L][]
end
