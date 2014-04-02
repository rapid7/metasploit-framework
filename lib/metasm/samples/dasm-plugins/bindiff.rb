#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# metasm dasm plugin: asks to load a second program, and unleash the samples/bindiff fury
# usage: load the plugin, and a 2nd binary, disassemble functions in both, diff'em

require File.join(Metasm::Metasmdir, 'samples', 'bindiff.rb')

Gui::DasmWindow.new("bindiff target").promptopen("chose bindiff target") { |w|
	w.title = "#{w.widget.dasm.program.filename} - metasm bindiff"
	@bindiff_win = BinDiffWindow.new(self, w.widget.dasm)
}

