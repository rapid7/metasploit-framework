#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/opcodes'
require 'metasm/encode'

module Metasm
class Ia32
  class InvalidModRM < Exception ; end
  class ModRM
    # returns the byte representing the register encoded as modrm
    # works with Reg/SimdReg
    def self.encode_reg(reg, mregval = 0)
      0xc0 | (mregval << 3) | reg.val
    end

    # The argument is an integer representing the 'reg' field of the mrm
    #
    # caller is responsible for setting the adsz
    # returns an array, 1 element per possible immediate size (for un-reduce()able Expression)
    def encode(reg = 0, endianness = :little)
      reg = reg.val if reg.kind_of? Argument
      case @adsz
      when 16; encode16(reg, endianness)
      when 32; encode32(reg, endianness)
      end
    end

    private
    def encode16(reg, endianness)
      if not b
        # imm only
        return [EncodedData.new << (6 | (reg << 3)) << @imm.encode(:u16, endianness)]
      end

      imm = @imm.reduce if self.imm
      imm = nil if imm == 0
      ret = EncodedData.new
      ret <<
      case [@b.val, (@i.val if i)]
      when [3, 6], [6, 3]; 0
      when [3, 7], [7, 3]; 1
      when [5, 6], [6, 5]; 2
      when [5, 7], [7, 5]; 3
      when [6, nil]; 4
      when [7, nil]; 5
      when [5, nil]
        imm ||= 0
        6
      when [3, nil]; 7
      else raise InvalidModRM, 'invalid modrm16'
      end

      # add bits in the first octet of ret.data (1.9 compatibility layer)
      or_bits = lambda { |v|	# rape me
        if ret.data[0].kind_of? Integer
          ret.data[0] |= v
        else
          ret.data[0] = (ret.data[0].unpack('C').first | v).chr
        end
      }

      or_bits[reg << 3]

      if imm
        case Expression.in_range?(imm, :i8)
        when true
          or_bits[1 << 6]
          [ret << Expression.encode_imm(imm, :i8, endianness)]
        when false
          or_bits[2 << 6]
          [ret << Expression.encode_imm(imm, :a16, endianness)]
        when nil
          rets = ret.dup
          or_bits[1<<6]
          ret << @imm.encode(:i8, endianness)
          ret, rets = rets, ret	# or_bits uses ret
          or_bits[2<<6]
          ret << @imm.encode(:a16, endianness)
          [ret, rets]
        end
      else
        [ret]
      end
    end

    def encode32(reg, endianness)
      # 0 => [ [0      ], [1      ], [2      ], [3      ], [:sib      ], [:i32   ], [6      ], [7      ] ], \
      # 1 => [ [0, :i8 ], [1, :i8 ], [2, :i8 ], [3, :i8 ], [:sib, :i8 ], [5, :i8 ], [6, :i8 ], [7, :i8 ] ], \
      # 2 => [ [0, :i32], [1, :i32], [2, :i32], [3, :i32], [:sib, :i32], [5, :i32], [6, :i32], [7, :i32] ]
      #
      # b => 0  1  2  3  4  5+i|i 6  7
      # i => 0  1  2  3 nil   5   6  7

      ret = EncodedData.new << (reg << 3)

      # add bits in the first octet of ret.data (1.9 compatibility layer)
      or_bits = lambda { |v|	# rape me
        if ret.data[0].kind_of? Integer
          ret.data[0] |= v
        else
          ret.data[0] = (ret.data[0].unpack('C').first | v).chr
        end
      }

      if not self.b and not self.i
        or_bits[5]
        [ret << @imm.encode(:a32, endianness)]

      elsif not self.b and self.s != 1
        # sib with no b
        raise EncodeError, "Invalid ModRM #{self}" if @i.val == 4
        or_bits[4]
        s = {8=>3, 4=>2, 2=>1}[@s]
        imm = self.imm || Expression[0]
        fu = (s << 6) | (@i.val << 3) | 5
        fu = fu.chr if s >= 2	# rb1.9 encoding fix
        [ret << fu << imm.encode(:a32, endianness)]
      else
        imm = @imm.reduce if self.imm
        imm = nil if imm == 0

        if not self.i or (not self.b and self.s == 1)
          # no sib byte (except for [esp])
          b = self.b || self.i

          or_bits[b.val]
          ret << 0x24 if b.val == 4
        else
          # sib
          or_bits[4]

          i, b = @i, @b
          b, i = i, b if @s == 1 and (i.val == 4 or b.val == 5)

          raise EncodeError, "Invalid ModRM #{self}" if i.val == 4

          s = {8=>3, 4=>2, 2=>1, 1=>0}[@s]
          fu = (s << 6) | (i.val << 3) | b.val
          fu = fu.chr if s >= 2	# rb1.9 encoding fix
          ret << fu
        end

        imm ||= 0 if b.val == 5
        if imm
          case Expression.in_range?(imm, :i8)
          when true
            or_bits[1<<6]
            [ret << Expression.encode_imm(imm, :i8, endianness)]
          when false
            or_bits[2<<6]
            [ret << Expression.encode_imm(imm, :a32, endianness)]
          when nil
            rets = ret.dup
            or_bits[1<<6]
            ret << @imm.encode(:i8, endianness)
            rets, ret = ret, rets	# or_bits[] modifies ret directly
            or_bits[2<<6]
            ret << @imm.encode(:a32, endianness)
            [ret, rets]
          end
        else
          [ret]
        end
      end
    end
  end

  class Farptr
    def encode(endianness, atype)
      @addr.encode(atype, endianness) << @seg.encode(:u16, endianness)
    end
  end

  # returns all forms of the encoding of instruction i using opcode op
  # program may be used to create a new label for relative jump/call
  def encode_instr_op(program, i, op)
    base      = op.bin.dup
    oi        = op.args.zip(i.args)
    set_field = lambda { |f, v|
      v ||= 0		# ST => ST(0)
      fld = op.fields[f]
      base[fld[0]] |= v << fld[1]
    }

    size = i.prefix[:sz] || @size

    #
    # handle prefixes and bit fields
    #
    pfx = i.prefix.map { |k, v|
      case k
      when :jmp;  {:jmp => 0x3e, :nojmp => 0x2e}[v]
      when :lock; 0xf0
      when :rep;  {'repnz' => 0xf2, 'repz' => 0xf3, 'rep' => 0xf2}[v] # TODO
      end
    }.compact.pack 'C*'
    pfx << op.props[:needpfx] if op.props[:needpfx]

    if op.name == 'movsx' or op.name == 'movzx'
      pfx << 0x66 if size == 48-i.args[0].sz
    else
      opsz = op.props[:argsz]
      oi.each { |oa, ia|
        case oa
        when :reg, :reg_eax, :modrm, :modrmA, :mrm_imm
          raise EncodeError, "Incompatible arg size in #{i}" if ia.sz and opsz and opsz != ia.sz
          opsz = ia.sz
        end
      }
      pfx << 0x66 if (not op.props[:argsz] or opsz != op.props[:argsz]) and (
        (opsz and size == 48 - opsz) or (op.props[:opsz] and op.props[:opsz] != size))
      if op.props[:opsz] and size == 48 - op.props[:opsz]
        opsz = op.props[:opsz]
      end
    end
    opsz ||= size

    if op.props[:adsz] and size == 48 - op.props[:adsz]
      pfx << 0x67
      adsz = 48 - size
    end
    adsz ||= size
    # addrsize override / segment override
    if mrm = i.args.grep(ModRM).first
      if not op.props[:adsz] and ((mrm.b and mrm.b.sz != adsz) or (mrm.i and mrm.i.sz != adsz))
        pfx << 0x67
        adsz = 48 - adsz
      end
      pfx << [0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65][mrm.seg.val] if mrm.seg
    end


    #
    # encode embedded arguments
    #
    postponed = []
    oi.each { |oa, ia|
      case oa
      when :reg, :seg3, :seg3A, :seg2, :seg2A, :eeec, :eeed, :regfp, :regmmx, :regxmm
        # field arg
        set_field[oa, ia.val]
        pfx << 0x66 if oa == :regmmx and op.props[:xmmx] and ia.sz == 128
      when :imm_val1, :imm_val3, :reg_cl, :reg_eax, :reg_dx, :regfp0
        # implicit
      else
        postponed << [oa, ia]
      end
    }

    if !(op.args & [:modrm, :modrmA, :modrmxmm, :modrmmmx]).empty?
      # reg field of modrm
      regval = (base[-1] >> 3) & 7
      base.pop
    end

    # convert label name for jmp/call/loop to relative offset
    if op.props[:setip] and op.name[0, 3] != 'ret' and i.args.first.kind_of? Expression
      postlabel = program.new_label('post'+op.name)
      target = postponed.first[1]
      target = target.rexpr if target.kind_of? Expression and target.op == :+ and not target.lexpr
      postponed.first[1] = Expression[target, :-, postlabel]
    end

    #
    # append other arguments
    #
    ret = EncodedData.new(pfx + base.pack('C*'))

    postponed.each { |oa, ia|
      case oa
      when :farptr; ed = ia.encode(@endianness, "a#{opsz}".to_sym)
      when :modrm, :modrmA, :modrmmmx, :modrmxmm
        if ia.kind_of? ModRM
          ed = ia.encode(regval, @endianness)
          if ed.kind_of?(::Array)
            if ed.length > 1
              # we know that no opcode can have more than 1 modrm
              ary = []
              ed.each { |m|
                ary << (ret.dup << m)
              }
              ret = ary
              next
            else
              ed = ed.first
            end
          end
        else
          ed = ModRM.encode_reg(ia, regval)
        end
      when :mrm_imm; ed = ia.imm.encode("a#{adsz}".to_sym, @endianness)
      when :i8, :u8, :u16; ed = ia.encode(oa, @endianness)
      when :i; ed = ia.encode("a#{opsz}".to_sym, @endianness)
      else raise SyntaxError, "Internal error: want to encode field #{oa.inspect} as arg in #{i}"
      end

      if ret.kind_of?(::Array)
        ret.each { |e| e << ed }
      else
        ret << ed
      end
    }

    # we know that no opcode with setip accept both modrm and immediate arg, so ret is not an ::Array
    ret.add_export(postlabel, ret.virtsize) if postlabel

    ret
  end
end
end
