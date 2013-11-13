#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/z80/opcodes'
require 'metasm/render'

module Metasm
class Z80
  class Reg
    include Renderable
    def render ; [self.class.i_to_s[@sz][@i]] end
  end
  class Memref
    include Renderable
    def render
      r = ['(']
      r << @base if @base
      r << '+' if @base and @offset
      r << @offset if @offset
      r << ')'
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

  def gui_hilight_word_regexp_init
    ret = {}

    # { 'B' => 'B|BC', 'BC' => 'B|C|BC' }

    %w[BC DE HL].each { |w|
      l0, l1 = w.split(//)
      ret[l0] = "#{l0}#{l1}?"
      ret[l1] = "#{l0}?#{l1}"
      ret[w] = "#{l0}|#{l0}?#{l1}"
    }

    ret
  end

  def gui_hilight_word_regexp(word)
    @gui_hilight_word_hash ||= gui_hilight_word_regexp_init
    @gui_hilight_word_hash[word] or super(word)
  end

end
end
