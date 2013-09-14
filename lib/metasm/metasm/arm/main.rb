#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class ARM < CPU
  class Reg
    class << self
      attr_accessor :s_to_i, :i_to_s
    end
    @i_to_s = %w[r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 sp lr pc]
    @s_to_i = { 'wr' => 7, 'sb' => 9, 'sl' => 10, 'fp' => 11, 'ip' => 12, 'sp' => 13, 'lr' => 14, 'pc' => 15 }
    15.times { |i| @s_to_i["r#{i}"] = i }
    4.times { |i| @s_to_i["a#{i+1}"] = i }
    8.times { |i| @s_to_i["v#{i+1}"] = i+4 }

    attr_accessor :i, :stype, :shift, :updated
    def initialize(i, stype=:lsl, shift=0)
      @i = i
      @stype = stype
      @shift = shift
    end

    def symbolic
      r = self.class.i_to_s[@i].to_sym
      if @stype == :lsl and @shift == 0
        r
      else
        r	# TODO shift/rotate/...
      end
    end
  end

  class Memref
    attr_accessor :base, :offset, :sign, :incr
    def initialize(base, offset, sign=:+, incr=nil)
      @base, @offset, @sign, @incr = base, offset, sign, incr
    end

    def symbolic(len=4, orig=nil)
      o = @offset
      o = o.symbolic if o.kind_of? Reg
      p = Expression[@base.symbolic, @sign, o].reduce
      Indirection[p, len, orig]
    end
  end

  class RegList
    attr_accessor :list, :usermoderegs

    def initialize(l=[])
      @list = l
    end
  end

  def initialize(endianness = :little)
    super()
    @endianness = endianness
    @size = 32
  end

  def init_opcode_list
    init_latest
    @opcode_list
  end
end

class ARM_THUMB < ARM
end
end

