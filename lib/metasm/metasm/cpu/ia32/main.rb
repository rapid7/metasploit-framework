#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm

# The ia32 aka x86 CPU
# currently limited to 16 and 32bit modes
class Ia32 < CPU

  # some ruby magic to declare classes with index -> name association (registers)
  class Argument
    class << self
      # for subclasses
      attr_accessor :i_to_s, :s_to_i
    end

    private
    # index -> name, name -> index
    def self.simple_map(a)
      # { 1 => 'dr1' }
      @i_to_s = Hash[*a.flatten]
      # { 'dr1' => 1 }
      @s_to_i = @i_to_s.invert

      class_eval {
        attr_accessor :val
        def initialize(v)
          raise Exception, "invalid #{self.class} #{v}" unless self.class.i_to_s[v]
          @val = v
        end

        def ==(o)
          self.class == o.class and val == o.val
        end

        def self.from_str(s) new(@s_to_i[s]) end
      }
    end

    # size -> (index -> name), name -> [index, size]
    def self.double_map(h)
      # { 32 => { 1 => 'ecx' } }
      @i_to_s = h
      # { 'ecx' => [1, 32] }
      @s_to_i = {} ; @i_to_s.each { |sz, hh| hh.each_with_index { |r, i| @s_to_i[r] = [i, sz] } }

      class_eval {
        attr_accessor :val, :sz
        def initialize(v, sz)
          raise Exception, "invalid #{self.class} #{sz}/#{v}" unless self.class.i_to_s[sz] and self.class.i_to_s[sz][v]
          @val = v
          @sz = sz
        end

        def ==(o)
          self.class == o.class and val == o.val and sz == o.sz
        end

        def self.from_str(s)
          raise "Bad #{name} #{s.inspect}" if not x = @s_to_i[s]
          new(*x)
        end
      }
    end
  end


  # segment register: es, cs, ss, ds, fs, gs and the theoretical segr6/7
  class SegReg < Argument
    simple_map((0..7).zip(%w(es cs ss ds fs gs segr6 segr7)))
  end

  # debug register (dr0..dr3, dr6, dr7), and theoretical dr4/5
  class DbgReg < Argument
    simple_map((0..7).map { |i| [i, "dr#{i}"] })
  end

  # control register (cr0, cr2, cr3, cr4) and theoretical cr1/5/6/7
  class CtrlReg < Argument
    simple_map((0..7).map { |i| [i, "cr#{i}"] })
  end

  # test registers (tr0..tr7) (undocumented)
  class TstReg < Argument
    simple_map((0..7).map { |i| [i, "tr#{i}"] })
  end

  # floating point registers
  class FpReg < Argument
    simple_map((0..7).map { |i| [i, "ST(#{i})"] } << [nil, 'ST'])
  end

  # Single Instr Multiple Data register (mm0..mm7, xmm0..xmm7, ymm0..ymm7)
  class SimdReg < Argument
    double_map  64 => (0..7).map { |n| "mm#{n}" },
         128 => (0..7).map { |n| "xmm#{n}" },
         256 => (0..7).map { |n| "ymm#{n}" }
    def symbolic(di=nil) ; to_s.to_sym end
  end

  # general purpose registers, all sizes
  class Reg < Argument
    double_map  8 => %w{ al  cl  dl  bl  ah  ch  dh  bh},
         16 => %w{ ax  cx  dx  bx  sp  bp  si  di},
         32 => %w{eax ecx edx ebx esp ebp esi edi}

    Sym = @i_to_s[32].map { |s| s.to_sym }

    # returns a symbolic representation of the register:
    # eax => :eax
    # cx => :ecx & 0xffff
    # ah => (:eax >> 8) & 0xff
    def symbolic(di=nil)
      s = Sym[@val]
      if @sz == 8 and to_s[-1] == ?h
        Expression[[Sym[@val-4], :>>, 8], :&, 0xff]
      elsif @sz == 8
        Expression[s, :&, 0xff]
      elsif @sz == 16
        Expression[s, :&, 0xffff]
      else
        s
      end
    end

    # checks if two registers have bits in common
    def share?(other)
      other.val % (other.sz >> 1) == @val % (@sz >> 1) and (other.sz != @sz or @sz != 8 or other.val == @val)
    end
  end

  # a far pointer
  # an immediate (numeric) pointer and an immediate segment selector
  class Farptr < Argument
    attr_accessor :seg, :addr
    def initialize(seg, addr)
      @seg, @addr = seg, addr
    end

    def ==(o)
      self.class == o.class and seg == o.seg and addr == o.addr
    end
  end

  # ModRM represents indirections in x86 (eg dword ptr [eax+4*ebx+12h])
  class ModRM < Argument
    # valid combinaisons for a modrm
    # ints are reg indexes, symbols are immediates, except :sib
    Sum = {
        16 => {
      0 => [ [3, 6], [3, 7], [5, 6], [5, 7], [6], [7], [:i16], [3] ],
      1 => [ [3, 6, :i8 ], [3, 7, :i8 ], [5, 6, :i8 ], [5, 7, :i8 ], [6, :i8 ], [7, :i8 ], [5, :i8 ], [3, :i8 ] ],
      2 => [ [3, 6, :i16], [3, 7, :i16], [5, 6, :i16], [5, 7, :i16], [6, :i16], [7, :i16], [5, :i16], [3, :i16] ]
        },
        32 => {
      0 => [ [0], [1], [2], [3], [:sib], [:i32], [6], [7] ],
      1 => [ [0, :i8 ], [1, :i8 ], [2, :i8 ], [3, :i8 ], [:sib, :i8 ], [5, :i8 ], [6, :i8 ], [7, :i8 ] ],
      2 => [ [0, :i32], [1, :i32], [2, :i32], [3, :i32], [:sib, :i32], [5, :i32], [6, :i32], [7, :i32] ]
        }
    }


    attr_accessor :adsz, :sz
    attr_accessor :seg
    attr_accessor :s, :i, :b, :imm

    # creates a new ModRM with the specified attributes:
    # - adsz (16/32), sz (8/16/32: byte ptr, word ptr, dword ptr)
    # - s, i, b, imm
    # - segment selector override
    def initialize(adsz, sz, s, i, b, imm, seg = nil)
      @adsz, @sz = adsz, sz
      @s, @i = s, i if i
      @b = b if b
      @imm = imm if imm
      @seg = seg if seg
    end

    # returns the symbolic representation of the ModRM (ie an Indirection)
    # segment selectors are represented as eg "segment_base_fs"
    # not present when same as implicit (ds:edx, ss:esp)
    def symbolic(di=nil)
      p = nil
      p = Expression[p, :+, @b.symbolic(di)] if b
      p = Expression[p, :+, [@s, :*, @i.symbolic(di)]] if i
      p = Expression[p, :+, @imm] if imm
      p = Expression["segment_base_#@seg", :+, p] if seg and seg.val != ((b && (@b.val == 4 || @b.val == 5)) ? 2 : 3)
      Indirection[p.reduce, @sz/8, (di.address if di)]
    end

    def ==(o)
      self.class == o.class and s == o.s and i == o.i and b == o.b and imm == o.imm and seg == o.seg and adsz == o.adsz and sz == o.sz
    end
  end


  # Create a new instance of an Ia32 cpu
  # arguments (any order)
  # - size in bits (16, 32) [32]
  # - instruction set (386, 486, pentium...) [latest]
  # - endianness [:little]
  def initialize(*a)
    super()
    @size = (a & [16, 32]).first || 32
    a.delete @size
    @endianness = (a & [:big, :little]).first || :little
    a.delete @endianness
    @family = a.pop || :latest
    raise "Invalid arguments #{a.inspect}" if not a.empty?
    raise "Invalid Ia32 family #{@family.inspect}" if not respond_to?("init_#@family")
  end

  # wrapper to transparently forward Ia32.new(64) to X86_64.new
  def self.new(*a)
    return X86_64.new(*a) if a.include? 64 and self == Ia32
    super(*a)
  end

  # initializes the @opcode_list according to @family
  def init_opcode_list
    send("init_#@family")
    @opcode_list
  end

  # defines some preprocessor macros to say who we are:
  # _M_IX86 = 500, _X86_, __i386__
  # pass any value in nodefine to just call super w/o defining anything of our own
  def tune_prepro(pp, nodefine = false)
    super(pp)
    return if nodefine
    pp.define_weak('_M_IX86', 500)
    pp.define_weak('_X86_')
    pp.define_weak('__i386__')
  end

  # returns a Reg/SimdReg object if the arg is a valid register (eg 'ax' => Reg.new(0, 16))
  # returns nil if str is invalid
  def str_to_reg(str)
    Reg.s_to_i.has_key?(str) ? Reg.from_str(str) : SimdReg.s_to_i.has_key?(str) ? SimdReg.from_str(str) : nil
  end

  # returns the list of Regs in the instruction arguments
  # may be converted into symbols through Reg#symbolic
  def instr_args_regs(i)
    i = i.instruction if i.kind_of?(DecodedInstruction)
    i.args.grep(Reg)
  end

  # returns the list of ModRMs in the instruction arguments
  # may be converted into Indirection through ModRM#symbolic
  def instr_args_memoryptr(i)
    i = i.instruction if i.kind_of?(DecodedInstruction)
    i.args.grep(ModRM)
  end

  # return the 'base' of the ModRM (Reg/nil)
  def instr_args_memoryptr_getbase(mrm)
    mrm.b || (mrm.i if mrm.s == 1)
  end

  # return the offset of the ModRM (Expression/nil)
  def instr_args_memoryptr_getoffset(mrm)
    mrm.imm
  end

  # define ModRM offset (eg to changing imm into an ExpressionString)
  def instr_args_memoryptr_setoffset(mrm, imm)
    mrm.imm = (imm ? Expression[imm] : imm)
  end

  def shortname
    "ia32#{'_16' if @size == 16}#{'_be' if @endianness == :big}"
  end
end
X86 = Ia32
end
