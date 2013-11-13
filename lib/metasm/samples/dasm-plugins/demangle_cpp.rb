#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin: try to demangle all labels as c++ names, add them as
# comment if successful

def demangle_all_cppnames
  cnt = 0
  prog_binding.each { |name, addr|
    cname = name.sub(/^thunk_/, '')
    if dname = demangle_cppname(cname)
      cnt += 1
      add_comment(addr, dname)
      each_xref(addr, :x) { |xr|
        if di = di_at(xr.origin)
          di.add_comment dname
          di.comment.delete "x:#{name}"
        end
      }
    end
  }
  cnt
end

if gui
  demangle_all_cppnames
  gui.gui_update
end
