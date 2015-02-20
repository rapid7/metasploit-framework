#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


# metasm dasm plugin
# finds instances of indirect calls a la call [ecx+40h], backtraces ecx, comments with the C++ object function pointer name
# if the backtracked object has no type, prompt for a C structure name.

# TODO simpler gui interface to set [base+off] =>  ; struct->member

@indirect_call_struct = {}
def solve_indirect_call_set_struct(ptr, struct)
  struct = @c_parser.toplevel.struct[struct] if struct.kind_of? String
  raise 'no such struct' if not struct
  @indirect_call_struct[ptr] = struct
end

def solve_indirect_calls
  @decoded.values.grep(DecodedInstruction).each { |di|
    next if not di.opcode.props[:saveip]	# only calls
    fptr = get_xrefs_x(di)
    next if fptr.to_a.length != 1
    fptr = Expression[fptr.first].reduce_rec
    next if not fptr.kind_of? Indirection
    next if not fptr.pointer.lexpr.kind_of? Symbol
    next if not fptr.pointer.rexpr.kind_of? Integer
    obj = backtrace(fptr.pointer.lexpr, di.address)
    obj.delete Expression::Unknown
    next if obj.length != 1
    obj = obj.first
    obj = Expression[obj].reduce_rec
    next if not obj.kind_of? Indirection
    obj = obj.pointer	# vtable ptr -> object ptr

    if not struct = @indirect_call_struct[obj]
      struct = yield obj if block_given?
      solve_indirect_call_set_struct(obj, struct || :none)
    end

    if struct.kind_of? C::Struct and fld = struct.members.find { |m| struct.offsetof(c_parser, m) == fptr.pointer.rexpr } and fld.name
      di.add_comment "#{struct.name || obj}->#{fld.name}"
      di.comment.delete 'x:unknown'
    end
  }
end

if gui
  solve_indirect_calls { |ptr|
    gui.inputbox("struct name for object at #{ptr}") { |name|
      solve_indirect_call_set_struct(ptr, name)
      # re-solve everything, cause we're called only once but many indirect calls may use ptr
      solve_indirect_calls
      gui.gui_update
    }
  }
  gui.gui_update
  nil
end
