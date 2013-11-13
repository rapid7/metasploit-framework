#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/main'

module Metasm
class Python < CPU
  def initialize(prog = nil)
    super()
    @program = prog
    @endianness = (prog.respond_to?(:endianness) ? prog.endianness : :little)
    @size = (prog.respond_to?(:size) ? prog.size : 32)
  end

  class Var
    include Renderable

    attr_accessor :i

    def initialize(i); @i = i end

    def ==(o)
      o.class == self.class and o.i == i
    end

    def symbolic; "var_#{@i}".to_sym end

    def render
      ["var_#@i"]
    end

  end
end
end
