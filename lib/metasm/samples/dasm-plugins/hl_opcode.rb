#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm GUI plugin: hilight lines of code based on the opcode name
if gui
  @gui_opcode_color = {
    :call => :green_bg,
    :jmp  => :red_bg,
    :jcc  => :orange_bg,
  }

  obg = gui.bg_color_callback	# chain old callback
  gui.bg_color_callback = lambda { |a|
    if di = di_at(a) and pr = di.opcode.props
      if pr[:saveip] and (@function[di.block.to_normal.to_a.first] or di.block.to_subfuncret.to_a.first)
        # don't color call+pop
        @gui_opcode_color[:call]
      elsif pr[:stopexec]
        @gui_opcode_color[:jmp]
      elsif pr[:setip]
        @gui_opcode_color[:jcc]
      else
        obg[a] if obg
      end
    else
      obg[a] if obg
    end
  }
end
