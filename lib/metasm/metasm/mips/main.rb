#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm
class MIPS < CPU
  class Reg
    class << self
      attr_accessor :s_to_i, :i_to_s
    end
    @s_to_i = {}
    @i_to_s = {}
    (0..31).each { |i| @s_to_i["r#{i}"] = @s_to_i["$r#{i}"] = @s_to_i["$#{i}"] = i }
    %w[zero at v0 v1 a0 a1 a2 a3
         t0 t1 t2 t3 t4 t5 t6 t7
         s0 s1 s2 s3 s4 s5 s6 s7
         t8 t9 k0 k1 gp sp fp ra].each_with_index { |r, i| @s_to_i[r] = @s_to_i['$'+r] = i ; @i_to_s[i] = '$'+r }

    attr_accessor :i
    def initialize(i)
      @i = i
    end

    Sym = @i_to_s.sort.map { |k, v| v.to_sym }
    def symbolic ; @i == 0 ? 0 : Sym[@i] end
  end

  class FpReg
    class << self
      attr_accessor :s_to_i, :i_to_s
    end
    @i_to_s = (0..31).map { |i| "$f#{i}" }
    @s_to_i = (0..31).inject({}) { |h, i| h.update "f#{i}" => i, "$f#{i}" => i }

    attr_accessor :i
    def initialize(i)
      @i = i
    end
  end

  class Memref
    attr_accessor :base, :offset
    def initialize(base, offset)
      @base, @offset = base, offset
    end

    def symbolic(orig)
      p = nil
      p = Expression[p, :+, @base.symbolic] if base
      p = Expression[p, :+, @offset] if offset
      Indirection[p.reduce, 4, orig]
    end
  end

  def initialize(endianness = :big, family = :latest)
    super()
    @endianness = endianness
    @size = 32
    @family = family
  end

  def init_opcode_list
    send("init_#@family")
    @opcode_list
  end
end
end

