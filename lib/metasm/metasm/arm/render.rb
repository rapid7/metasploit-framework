#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/render'
require 'metasm/arm/opcodes'

module Metasm
class ARM
  class Reg
    include Renderable
    def render
      r = self.class.i_to_s[@i]
      r += '!' if updated
      if @stype == :lsl and @shift == 0
        [r]
      elsif @stype == :ror and @shift == 0
        ["#{r} RRX"]
      else
        case s = @shift
        when Integer; s = Expression[s]
        when Reg; s = self.class.i_to_s[s.i]
        end
        ["#{r} #{@stype.to_s.upcase} #{s}"]
      end
    end
  end

  class Memref
    include Renderable
    def render
      o = @offset
      o = Expression[o] if o.kind_of? Integer
      case @incr
      when nil;   ['[', @base, ', ', o, ']']
      when :pre;  ['[', @base, ', ', o, ']!']
      when :post; ['[', @base, '], ', o]
      end
    end
  end

  class RegList
    include Renderable
    def render
      r = ['{']
      @list.each { |l| r << l << ', ' }
      r[-1] = '}'
      r << '^' if usermoderegs
      r
    end
  end
end
end

