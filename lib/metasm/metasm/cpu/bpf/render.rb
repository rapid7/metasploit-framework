#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/bpf/opcodes'
require 'metasm/render'

module Metasm
class BPF
  class Reg
    include Renderable
    def render ; [@v.to_s] end
  end
  class MemRef
    include Renderable
    def render
      r = []
      r << memtype
      r << [nil, ' byte ', ' word ', nil, ' dword '][@msz]
      r << '['
      r << @base if @base
      r << '+' if @base and @offset
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
