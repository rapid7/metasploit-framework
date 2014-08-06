#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class Z80 < CPU
  class Reg
    class << self
      attr_accessor :s_to_i, :i_to_s
    end
    @i_to_s = { 8 => { 0 => 'B', 1 => 'C', 2 => 'D', 3 => 'E',
           4 => 'H', 5 => 'L', 7 => 'A' },
         16 => { 0 => 'BC', 1 => 'DE', 2 => 'HL', 3 => 'SP',
           4 => 'AF' } }	# AF is 3 too
    @s_to_i = @i_to_s.inject({}) { |h, (sz, rh)|
      h.update rh.inject({}) { |hh, (i, n)|
        hh.update n => [sz, i] } }

    attr_accessor :sz, :i
    def initialize(sz, i)
      @sz = sz
      @i = i
    end

    def symbolic(orig=nil) ; to_s.to_sym ; end

    def self.from_str(s)
      raise "Bad name #{s.inspect}" if not x = @s_to_i[s]
      new(*x)
    end
  end

  class Memref
    attr_accessor :base, :offset, :sz
    def initialize(base, offset, sz=nil)
      @base = base
      offset = Expression[offset] if offset
      @offset = offset
      @sz = sz
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

