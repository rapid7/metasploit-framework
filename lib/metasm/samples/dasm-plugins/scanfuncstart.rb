#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: scan the memory for a 'ret' which could indicate the beginning of the current function
# (x86 only)
def scanfuncstart(addr)
  if o = (1..16).find { |off| @decoded[addr-off].kind_of? DecodedInstruction } and @decoded[addr-o].bin_length == o
    addr -= o
  end
  if @decoded[addr].kind_of? DecodedInstruction
    fs = find_function_start(addr)
    return fs if fs != addr
  end
  edata = get_edata_at(addr)
  if o = (1..1000).find { |off|
    @decoded[addr-off-1] or
    edata.data[edata.ptr-off-1] == ?\xcc or
    edata.data[edata.ptr-off-1] == ?\xc3 or
    edata.data[edata.ptr-off-3] == ?\xc2
  }
    o -= @decoded[addr-o-1].bin_length-1 if @decoded[addr-o-1].kind_of? DecodedInstruction
    addr-o
  end
end

if gui
  gui.keyboard_callback_ctrl[?P] = lambda { |*a|
    if o = scanfuncstart(gui.curaddr)
      gui.focus_addr(o)
    end
    true
  }
end
