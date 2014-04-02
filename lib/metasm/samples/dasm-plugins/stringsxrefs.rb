#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin
# walks all disassembled instructions referencing an address
# if this address points a C string, show that in the instruction comments
# esp. useful after a disassemble_fast

def stringsxrefs(maxsz = 32)
  @decoded.each_value { |di|
    next if not di.kind_of?(DecodedInstruction)
    di.instruction.args.grep(Expression).each { |e|
      if str = decode_strz(e) and str.length >= 4 and str =~ /^[\x20-\x7e]*$/
        di.add_comment str[0, maxsz].inspect
        add_xref(normalize(e), Xref.new(:r, di.address, 1))
      end
    }
  }
  nil
end

if gui
  stringsxrefs
  gui.gui_update
end
