#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/cy16/opcodes'
require 'metasm/render'

module Metasm
class CY16
  class Reg
    include Renderable
    def render ; [self.class.i_to_s[@i]] end
  end
  class Memref
    include Renderable
    def render
      r = []
      r << (@sz == 1 ? 'byte ptr ' : 'word ptr ')
      r << '['
      r << @base if @base
      r << '++' if @autoincr
      r << ' + ' if @base and @offset
      r << @offset if @offset
      r << ']'
    end
  end

  def render_instruction(i)
    r = []
    r << i.opname
    if not i.args.empty?
      r << ' '
      i.args.each { |a_| r << a_ << ', ' }
      r.pop
    end
    r
  end
end
end
