#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/render'

module Metasm
class PowerPC < CPU
  class Reg
    include Renderable

    def ==(o)
      o.class == self.class and (not respond_to?(:i) or o.i == i)
    end
  end

  # general purpose reg
  class GPR < Reg
    attr_accessor :i
    def initialize(i)
      @i = i
    end

    Sym = (0..31).map { |i| "r#{i}".to_sym }
    Sym[1] = :sp
    def symbolic ; Sym[@i] end
    def render ; [@i == 1 ? 'sp' : "r#@i"] end
  end

  # special purpose reg
  class SPR < Reg
    class << self
      attr_accessor :s_to_i, :i_to_s
    end
    @s_to_i = {'xer' => 1, 'lr' => 8, 'ctr' => 9, 'dec' => 22, 'srr0' => 26, 'srr1' => 27,
      'sprg0' => 272, 'sprg1' => 273, 'sprg2' => 274, 'sprg3' => 275, 'pvr' => 287}
    @i_to_s = @s_to_i.invert

    attr_accessor :i
    def initialize(i)
      @i = i
    end

    Sym = @i_to_s.sort.inject({}) { |h, (k, v)| h.update k => v.to_sym }
    def symbolic ; Sym[@i] end
    def render ; [self.class.i_to_s[@i] || "spr#@i"] end
  end

  # floating point
  class FPR
    attr_accessor :i
    def initialize(i)
      @i = i
    end

    include Renderable
    def render ; ["fp#@i"] end
  end

  # machine state reg
  class MSR < Reg
    def symbolic ; :msr end
    def render ; ['msr'] end
  end

  # condition reg (7 regs * 4 bits : lt, gt, eq, of)
  class CR < Reg
    attr_accessor :i
    def initialize(i)
      @i = i
    end

    def symbolic ; "cr#@i".to_sym end
    def render ; ["cr#@i"] end
  end

  # indirection : reg+reg or reg+16b_off
  # r0 may mean 0 in some cases (stwx)
  class Memref
    attr_accessor :base, :offset
    def initialize(base, offset)
      @base, @offset = base, offset
    end

    def symbolic(orig)
      b = @base.symbolic
      b = nil if b == :r0	# XXX is it true ?
      o = @offset
      o = o.symbolic if o.kind_of? Reg
      Indirection[Expression[b, :+, o].reduce, 4, orig]
    end

    include Renderable
    def render
      if @offset.kind_of? Reg
        ['(', @base, ' + ', @offset, ')']
      else
        [@offset, '(', @base, ')']
      end
    end
  end

  def initialize
    super()
    @endianness = :big
    @size = 32
  end

  def init_opcode_list
    init
  end

  def render_instruction(i)
    r = [i.opname]
    if not i.args.empty?
      r << ' '
      i.args.each { |a|
        r << a << ', '
      }
      r.pop
    end
    r
  end
end
PPC = PowerPC
end
