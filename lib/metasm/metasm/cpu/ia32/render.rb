#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/ia32/opcodes'
require 'metasm/render'

# XXX move context in another file ?
module Metasm
class Ia32
  class Argument
    include Renderable
  end

  [SegReg, DbgReg, TstReg, CtrlReg, FpReg].each { |c| c.class_eval {
    def render ; [self.class.i_to_s[@val]] end
  } }
  [Reg, SimdReg].each { |c| c.class_eval {
    def render ; [self.class.i_to_s[@sz][@val]] end
    def context ; {'set sz' => lambda { |s| @sz = s }} end
  } }

  class Farptr
    def render
      [@seg, ':', @addr]
    end
  end

  class ModRM
    def qualifier(sz)
      {
       8 => 'byte',
      16 => 'word',
      32 => 'dword',
      64 => 'qword',
      128 => 'oword'
      }.fetch(sz) { |k| "_#{sz}bits" }
    end

    attr_accessor :instruction
    def render
      r = []
      r << ( qualifier(@sz) << ' ptr ' ) if @sz and (not instruction or not @instruction.args.find { |a| a.kind_of? Reg and a.sz == @sz })
      r << @seg << ':' if seg

      e = nil
      e = Expression[e, :+, @b] if b
      e = Expression[e, :+, @imm] if imm
      e = Expression[e, :+, (@s == 1 ? @i : [@s, :*, @i])] if s
      r << '[' << e << ']'
    end

    def context
      {'set targetsz' => lambda { |s| @sz = s },
       'set seg' => lambda { |s| @seg = Seg.new s }}
    end
  end

  def render_instruction(i)
    r = []
    if pfx = i.prefix
      r << 'lock ' if pfx[:lock]
      r << pfx[:rep] << ' ' if pfx[:rep]
      r << pfx[:jmphint] << ' ' if pfx[:jmphint]
      r << 'seg_' << pfx[:seg] << ' ' if pfx[:seg]
    end
    r << i.opname
    sep = ' '
    i.args.each { |a|
      a.instruction = i if a.kind_of? ModRM
      r << sep << a
      sep = ', '
    }
    r
  end

  def instruction_context(i)
    # XXX
    h = {}
    op = opcode_list_byname[i.opname].first
    if i.prefix and i.prefix[:rep]
      h['toogle repz'] = lambda { i.prefix[:rep] = {'repnz' => 'repz', 'repz' => 'repnz'}[i.prefix[:rep]] } if op.props[:stropz]
      h['rm rep']      = lambda { i.prefix.delete :rep }
    else
      h['set rep']     = lambda { (i.prefix ||= {})[:rep] = 'rep'  } if op.props[:strop]
      h['set rep']     = lambda { (i.prefix ||= {})[:rep] = 'repz' } if op.props[:stropz]
    end
    if i.args.find { |a| a.kind_of? ModRM and a.seg }
      h['rm seg'] = lambda { i.args.find { |a| a.kind_of? ModRM and a.seg }.seg = nil }
    end
    h['toggle lock'] = lambda { (i.prefix ||= {})[:lock] = !i.prefix[:lock] }
    h
  end

  def gui_hilight_word_regexp_init
    ret = {}

    %w[a b c d].each { |r|
      ret["#{r}l"] = "e?#{r}x|#{r}l"
      ret["#{r}h"] = "e?#{r}x|#{r}h"
      ret["#{r}x"] = ret["e#{r}x"] = "e?#{r}x|#{r}[hl]"
    }

    %w[sp bp si di].each { |r|
      ret[r] = ret["e#{r}"] = "e?#{r}"
    }

    ret
  end

  def gui_hilight_word_regexp(word)
    @gui_hilight_word_hash ||= gui_hilight_word_regexp_init
    @gui_hilight_word_hash[word] or super(word)
  end
end
end
