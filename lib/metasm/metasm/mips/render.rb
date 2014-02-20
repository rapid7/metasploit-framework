#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/mips/opcodes'
require 'metasm/render'

module Metasm
class MIPS
  class Reg
    include Renderable
    def render ; [self.class.i_to_s[@i]] end
  end
  class FpReg
    include Renderable
    def render ; [self.class.i_to_s[@i]] end
  end
  class Memref
    include Renderable
    def render ; [@offset, '(', @base, ')'] end
  end

  def render_instruction(i)
    r = []
    r << i.opname
    if not i.args.empty?
      r << ' '
      if (a = i.args.first).kind_of? Expression and a.op == :- and a.lexpr.kind_of? String and a.rexpr.kind_of? String and opcode_list_byname[i.opname].first.props[:setip]
        # jmp foo is stored as jmp foo - bar ; bar:
        r << a.lexpr
      else
        i.args.each { |a_|
          r << a_ << ', '
        }
        r.pop
      end
    end
    r
  end
end
end
