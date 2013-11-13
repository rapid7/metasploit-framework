#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin
# walks all disassembled instructions referencing an address
# if the address is a label, update the instruction to use the label
# esp. useful after a disassemble_fast, with a .map file

def addrtolabel
  bp = prog_binding.invert
  @decoded.each_value { |di|
    next if not di.kind_of?(DecodedInstruction)
    di.each_expr { |e|
      next unless e.kind_of?(Expression)
      if l = bp[e.lexpr]
        add_xref(e.lexpr, Xref.new(:addr, di.address))
        e.lexpr = Expression[l]
      end
      if l = bp[e.rexpr]
        add_xref(e.rexpr, Xref.new(:addr, di.address))
        e.rexpr = (e.lexpr ? Expression[l] : l)
      end
    }
  }
  nil
end

if gui
  addrtolabel
  gui.gui_update
end
