#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/main'

module Metasm

class Sh4 < CPU
  def initialize(e = :little, transfersz = 0, fpprecision = 0)
    super()
    @endianness = e

    # transfer size mode
    # When SZ = 1 and big endian mode is selected, FMOV can
    # be used for double-precision floating-point data load or
    # store operations. In little endian mode, two 32-bit data size
    # moves must be executed, with SZ = 0, to load or store a
    # double-precision floating-point number.
    transfersz = 0 if @endianness == :little
    @transfersz = transfersz

    # PR = 0 : Floating point instructions are executed as single
    # precision operations.
    # PR = 1 : Floating point instructions are executed as double-
    # precision operations (the result of instructions for
    # which double-precision is not supported is undefined).
    # Setting [transfersz = fpprecision = 1] is reserved.
    # FPU operations are undefined in this mode.
    @fpprecision = fpprecision

    @size = 32
  end

  class Reg
    include Renderable

    def ==(o)
      o.class == self.class and (not respond_to?(:i) or o.i == i)
    end
  end

  # general purpose reg
  class GPR < Reg
    attr_accessor :i

    def initialize(i); @i = i end
    Sym = (0..15).map { |i| "r#{i}".to_sym }

    def symbolic ; Sym[@i] end

    def render ; ["r#@i"] end
  end

  class RBANK < Reg
    attr_accessor :i

    def initialize(i); @i = i end
    Sym = (0..7).map { |i| "r#{i}_bank".to_sym }

    def symbolic ; Sym[@i] end

    def render ; ["r#{@i}_bank"] end
  end

  # floatting-point registers
  class FR < Reg
    attr_accessor :i

    def initialize(i); @i = i end
    Sym = (0..15).map { |i| "fr#{i}".to_sym }

    def symbolic ; Sym[@i] end

    def render ; ["fr#@i"] end
  end

  # DR registers: double-precision floating-point registers
  # DR0 = {FR0, FR1}
  # DR2 = {FR2, FR3}
  # DR4 = {FR4, FR5}
  # DR6 = {FR6, FR7}
  # DR8 = {FR8, FR9}
  # DR10 = {FR10, FR11}
  # DR12 = {FR12, FR13}
  # DR14 = {FR14, FR15}
  class DR < Reg
    attr_accessor :i

    def initialize(i); @i = i end
    Sym = (0..7).map { |i| "dr#{i*2}".to_sym }

    def symbolic ; Sym[@i/2] end

    def render ; ["dr#@i"] end
  end

  # Single-precision floating-point vector registers
  # FV0 = {FR0, FR1, FR2, FR3}
  # FV4 = {FR4, FR5, FR6, FR7},
  # FV8 = {FR8, FR9, FR10, FR11}
  # FV12 = {FR12, FR13, FR14, FR15}
  class FVR < Reg
    attr_accessor :i

    def initialize(i); @i = i end
    Sym = (0..3).map { |i| "fv#{i*4}".to_sym }

    def symbolic ; Sym[@i/4] end

    def render ; ["fv#@i"] end
  end

  # Single-precision floating-point extended registers
  class XFR < Reg
    attr_accessor :i

    def initialize(i); @i = i end
    Sym = (0..15).map { |i| "xf#{i}".to_sym }

    def symbolic ; Sym[@i] end

    def render ; ["xf#@i"] end
  end

  # XD registers: single-precision floating-point vector registers
  # XD0 = {XF0, XF1}
  # XD2 = {XF2, XF3}
  # XD4 = {XF4, XF5}
  # XD6 = {XF6, XF7}
  # XD8 = {XF8, XF9}
  # XD10 = {XF10, XF11}
  # XD12 = {XF12, XF13}
  # XD14 = {XF14, XF15}
  class XDR < Reg
    attr_accessor :i

    def initialize(i); @i = i end
    Sym = (0..7).map { |i| "xd#{i*2}".to_sym }

    def symbolic ; Sym[@i/2] end

    def render ; ["xd#@i"] end
  end

  # Single-precision floating-point extended register matrix
  class XMTRX < Reg
    def symbolic ; :xmtrx ; end
    def render ; ['xmtrx'] ; end
  end


  # Multiply-and-accumulate register high
  class MACH < Reg

    def symbolic ; :mach end
    def render ; ['mach'] end
  end

  # Multiply-and-accumulate register low
  class MACL < Reg

    def symbolic ; :macl end
    def render ; ['macl'] end
  end

  # Procedure register
  class PR < Reg

    def symbolic ; :pr end
    def render ; ['pr'] end
  end

  # Floating-point communication register
  class FPUL < Reg

    def symbolic ; :fpul end
    def render ; ['fpul'] end
  end

  # Program counter
  class PC < Reg

    def symbolic ; :pc end
    def render ; ['pc'] end
  end

  # Floating-point status/control register
  class FPSCR < Reg

    def symbolic ; :fpscr end
    def render ; ['fpscr'] end
  end

  #----------------------- Control registers -----------------------------

  # Status register
  class SR < Reg

    def symbolic ; :sr end
    def render ; ['sr'] end
  end

  # Saved status register
  class SSR < Reg

    def symbolic ; :ssr end
    def render ; ['ssr'] end
  end

  # Saved program counter
  class SPC < Reg

    def symbolic ; :spc end
    def render ; ['spc'] end
  end

  # Global base register
  class GBR < Reg

    def symbolic ; :spc end
    def render ; ['gbr'] end
  end

  # Vector base register
  class VBR < Reg

    def symbolic ; :spc end
    def render ; ['vbr'] end
  end

  # Saved general register
  class SGR < Reg

    def symbolic ; :sgr end
    def render ; ['sgr'] end
  end

  # Debug base register
  class DBR < Reg

    def symbolic ; :dbr end
    def render ; ['dbr'] end
  end

  class Memref
    # action: pre/post (inc/dec)rement
    attr_accessor :base, :disp, :action

    def initialize(base, offset, action = nil)
      base = Expression[base] if base.kind_of? Integer
      @base, @disp, @action = base, offset, action
    end

    def symbolic(orig=nil, sz=32)
      b = @base
      b = b.symbolic if b.kind_of? Reg

      if disp
        o = @disp
        o = o.symbolic if o.kind_of? Reg
        e = Expression[b, :+, o].reduce
      else
        e = Expression[b].reduce
      end

      Indirection[e, sz, orig]
    end

    include Renderable

    def render
      if @disp
        ['@(', @base, ',', @disp, ')']
      else
        case @action
        when :pre then ['@-', @base]
        when :post then ['@', @base, '+']
        else ['@', @base]
        end
      end
    end

  end

  def init_opcode_list
    init
  end

end
end
