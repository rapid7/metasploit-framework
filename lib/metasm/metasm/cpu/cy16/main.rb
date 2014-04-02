#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class CY16 < CPU
  class Reg
    class << self
      attr_accessor :s_to_i, :i_to_s
    end
    @i_to_s = (0..14).inject({}) { |h, i| h.update i => "r#{i}" }
    @i_to_s[15] = 'sp'
    @s_to_i = @i_to_s.invert

    attr_accessor :i
    def initialize(i)
      @i = i
    end

    def symbolic(orig=nil) ; to_s.to_sym ; end

    def self.from_str(s)
      raise "Bad name #{s.inspect}" if not x = @s_to_i[s]
      new(x)
    end
  end

  class Memref
    attr_accessor :base, :offset, :sz, :autoincr
    def initialize(base, offset, sz=nil, autoincr=nil)
      @base = base
      offset = Expression[offset] if offset
      @offset = offset
      @sz = sz
      @autoincr = autoincr
    end

    def symbolic(orig)
      p = nil
      p = Expression[p, :+, @base.symbolic] if base
      p = Expression[p, :+, @offset] if offset
      Indirection[p.reduce, @sz, orig]
    end
  end

  def initialize(family = :latest)
    super()
    @endianness = :little
    @size = 16
    @family = family
  end

  def init_opcode_list
    send("init_#@family")
    @opcode_list
  end
end
end

