#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/x86_64/opcodes'
require 'metasm/render'

module Metasm
class X86_64
  def gui_hilight_word_regexp_init
    ret = {}

    %w[a b c d].each { |r|
      ret["#{r}l"] = "[re]?#{r}x|#{r}l"
      ret["#{r}h"] = "[re]?#{r}x|#{r}h"
      ret["#{r}x"] = ret["e#{r}x"] = ret["r#{r}x"] = "[re]?#{r}x|#{r}[hl]"
    }

    %w[sp bp si di].each { |r|
      ret["#{r}l"] = ret[r] = ret["e#{r}"] = ret["r#{r}"] = "[re]?#{r}|#{r}l"
    }

    (8..15).each { |i|
      r = "r#{i}"
      ret[r+'b'] = ret[r+'w'] = ret[r+'d'] = ret[r] = "#{r}[bwd]?"
    }

    ret['eip'] = ret['rip'] = '[re]ip'

    ret
  end
end
end
