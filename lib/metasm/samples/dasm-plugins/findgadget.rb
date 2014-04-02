#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2011 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin
# scan for a given asm instruction sequence (all encodings)
# add the G dasm-gui shortcut, the input change ';' for line splits

def findgadget_asm_to_regex(asm)
  fullre = ''
  asm = asm.gsub(';', "\n")

  sc = Shellcode.new(@cpu)
  sc.parse asm
  sc.source.each { |i|
    case i
    when Data
      opts_edata = i.encode(@cpu.endianness)
    when Instruction
      opts_edata = @cpu.encode_instruction(sc, i)
    else
      raise "cant scan for #{i}"
    end

    opts_edata = [opts_edata] if opts_edata.kind_of?(EncodedData)

    opts_re = opts_edata.map { |ed|
      # Regexp.escape ed.data, with relocs replaced with '.'
      re = ''
      off = 0
      ed.reloc.sort.each { |o, rel|
        re << Regexp.escape(ed.data[off...o])
        re << ('.' * rel.length)
        off = o + rel.length
      }
      re << Regexp.escape(ed.data[off..-1])
    }
    fullre << '(' << opts_re.join('|') << ')'
  }

  Regexp.new(fullre, Regexp::MULTILINE, 'n')
end

# parse asm to a regexp, return the list of addresses matching
def findgadget_asm(asm)
  pattern_scan(findgadget_asm_to_regex(asm))
end

def findgadget_prompt
  gui.inputbox("source for the gadget - separate with ;") { |asm|
    lst = findgadget_asm(asm)
    list = [['address', 'section']]
    sections = section_info
    list += lst.map { |addr|
      # [name, addr, len, misc]
      if s = sections.find { |s_| s_[1] <= addr and s_[1] + s_[2] > addr }
        s = s[0]
      else
        s = '?'
      end
      [Expression[addr], s]
    }
    gui.listwindow("gadgetscan for #{asm}", list) { |args| gui.focus_addr(args[0]) }
  }
end

if gui
  gui.keyboard_callback[?G] = lambda { |*a| findgadget_prompt }
  w = gui.toplevel
  w.addsubmenu(w.find_menu('Actions'), 'Scan for _Gadget', 'G') { findgadget_prompt }
  w.update_menu
  :success
end
