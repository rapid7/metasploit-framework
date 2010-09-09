#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm GUI plugin: hilight lines of code based on the opcode name
if gui
	@gui_opcode_color = { 'call' => '8ff', 'jmp' => 'f8f' }

	obg = gui.bg_color_callback	# chain old callback
	gui.bg_color_callback = lambda { |a|
		if di = di_at(a) and col = @gui_opcode_color[di.opcode.name]
			col
		else
			obg[a] if obg
		end
	}
end
