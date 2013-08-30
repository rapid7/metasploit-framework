#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin
# decompose immediate values from C constants, adds a comment with the decomposition

# find immediate exprs in the instruction at addr, yield them
def imm_to_const(addr)
  return if not di = di_at(addr)
  # TODO enter into memrefs ?
  di.instruction.args.grep(Expression).each { |a|
    i = a.reduce
    next if not i.kind_of? Integer
    next if not cstbase = yield(i)
    if c = imm_to_const_decompose(i, cstbase)
      di.add_comment c
    end
  }
end

# find the bitwise decomposition of imm into constants whose name include cstbase
def imm_to_const_decompose(imm, cstbase)
  cstbase = /#{cstbase}/i if not cstbase.kind_of? Regexp
  dict = {}
  c_parser.lexer.definition.keys.grep(cstbase).each { |cst|
    if i = c_parser.macro_numeric(cst)
      dict[cst] = i
    end
  }
  c_parser.toplevel.symbol.each { |k, v|
    dict[k] = v if v.kind_of? Integer and k =~ cstbase
  }
  dict.delete_if { |k, v| imm & v != v }
  if cst = dict.index(imm)
    cst
  else
    # a => 1, b => 2, c => 4, all => 7: discard abc, keep 'all'
    dict.delete_if { |k, v| dict.find { |kk, vv| vv > v and vv & v == v } }
    dict.keys.join(' | ') if not dict.empty?
  end
end

if gui
  gui.keyboard_callback[?K] = lambda { |*a|
    addr = gui.curaddr
    imm_to_const(addr) { |i|
      gui.inputbox("const name for #{Expression[i]}") { |name|
        imm_to_const(addr) { |ii| name if ii == i }
        gui.gui_update
      }
      nil
    }
  }
end
