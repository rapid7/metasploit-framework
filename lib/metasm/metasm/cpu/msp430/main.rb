#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/main'

module Metasm

class MSP430 < CPU
  def initialize(e = :little)
    super()
    @endianness = e
    @size = 16
  end

  class Reg
    include Renderable
    Sym = (4..15).inject(0 => :pc, 1 => :sp, 2 => :flags, 3 => :rzero) { |h, i| h.update i => "r#{i}".to_sym }

    attr_accessor :i
    def initialize(i) ; @i = i end
    def symbolic ; Sym[@i] end
    def render ; [Sym[@i].to_s] end
    def ==(o) ; o.class == self.class and o.i == @i end
  end

  class Memref
    attr_accessor :base, :offset, :size, :postincr

    def initialize(base, offset = 0, size = nil, postincr = false)
      @base = base
      @offset = Expression[offset]
      @size = size
      @postincr = postincr
    end

    def symbolic(orig=nil)
      r = @base.symbolic if @base
      e = Expression[r, :+, @offset].reduce
      Indirection[e, (@size || 1), orig]
    end

    include Renderable

    def render
      b = @base
      b = @base.to_s + '++' if @base and @postincr
      p = Expression[b, :+, @offset].reduce
      Indirection[p, @size].render
    end
  end

  def init_opcode_list
    init
  end

  def dbg_register_list
    @dbg_register_list ||= Reg::Sym.sort.transpose.last
  end
end
end
