#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/x86_64/opcodes'
require 'metasm/encode'

module Metasm
class X86_64
  class ModRM
    def self.encode_reg(reg, mregval = 0)
      v = reg.kind_of?(Reg) ? reg.val_enc : reg.val & 7
      0xc0 | (mregval << 3) | v
    end

    def encode(reg = 0, endianness = :little)
      reg = reg.val if reg.kind_of? Ia32::Argument

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
        # imm only, use sib
        or_bits[4]
        imm = self.imm || Expression[0]
        [ret << ((4 << 3) | 5) << imm.encode(:i32, endianness)]

      elsif (self.b and self.b.val == 16) or (self.i and self.i.val == 16)	# rip+imm	(rip == addr of the octet after the current instr)
        # should have been filtered by #parse, but just in case
        raise "invalid rip addressing #{self}" if (self.i and self.b) or (self.s and self.s != 1)
        or_bits[5]
        imm = self.imm || Expression[0]
        [ret << imm.encode(:i32, endianness)]

      elsif not self.b and self.s != 1
        # sib with no b
        raise EncodeError, "Invalid ModRM #{self}" if @i.val == 4	# XXX 12 ?
        or_bits[4]
        s = {8=>3, 4=>2, 2=>1}[@s]
        imm = self.imm || Expression[0]
        fu = (s << 6) | (@i.val_enc << 3) | 5
        fu = fu.chr if s >= 2	# rb1.9 encoding fix
        [ret << fu << imm.encode(:i32, endianness)]
      else
        imm = @imm.reduce if self.imm
        imm = nil if imm == 0

        if not self.i or (not self.b and self.s == 1)
          # no sib byte (except for [esp])
          @s, @i, @b = nil, nil, @s if not self.b
          or_bits[@b.val_enc]
          ret << 0x24 if @b.val_enc == 4	# XXX val_enc ?
        else
          # sib
          or_bits[4]

          @b, @i = @i, @b if @s == 1 and @i.kind_of?(Reg) and (@i.val_enc == 4 or @b.val_enc == 5)

          raise EncodeError, "Invalid ModRM #{self}" if @i.val == 4

          s = {8=>3, 4=>2, 2=>1, 1=>0}[@s]
          fu = (s << 6) | (@i.val_enc << 3) | @b.val_enc
          fu = fu.chr if s >= 2	# rb1.9 encoding fix
          ret << fu
        end

        imm ||= 0 if @b.val_enc == 5
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

  # returns all forms of the encoding of instruction i using opcode op
  # program may be used to create a new label for relative jump/call
  def encode_instr_op(program, i, op)
    base      = op.bin.dup
    oi        = op.args.zip(i.args)
    set_field = lambda { |f, v|
      fld = op.fields[f]
      base[fld[0]] |= v << fld[1]
    }

    #
    # handle prefixes and bit fields
    #
    pfx = i.prefix.map { |k, v|
      case k
      when :jmp;  {:jmp => 0x3e, :nojmp => 0x2e}[v]
      when :lock; 0xf0
      when :rep;  {'repnz' => 0xf2, 'repz' => 0xf3, 'rep' => 0xf2}[v]
      when :jmphint; {'hintjmp' => 0x3e, 'hintnojmp' => 0x2e}[v]
      when :seg; [0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65][v.val]
      end
    }.compact.pack 'C*'

    rex_w = rex_r = rex_x = rex_b = 0
    if op.name == 'movsx' or op.name == 'movzx' or op.name == 'movsxd'
      case i.args[0].sz
      when 64; rex_w = 1
      when 32
      when 16; pfx << 0x66
      end
    elsif op.name == 'crc32'
      case i.args[1].sz
      when 64; rex_w = 1
      when 32;
      when 16; pfx << 0x66
      end
    else
      opsz = op.props[:argsz] || i.prefix[:sz]
      oi.each { |oa, ia|
        case oa
        when :reg, :reg_eax, :modrm, :mrm_imm
          raise EncodeError, "Incompatible arg size in #{i}" if ia.sz and opsz and opsz != ia.sz
          opsz = ia.sz
        end
      }
      opsz ||= 64 if op.props[:auto64]
      opsz = op.props[:opsz] if op.props[:opsz]	# XXX ?
      case opsz
      when 64; rex_w = 1 if not op.props[:auto64] and (not op.props[:argsz] or op.props[:opsz] == 64)
      when 32; raise EncodeError, "Incompatible arg size in #{i}" if op.props[:auto64]
      when 16; pfx << 0x66
      end
    end
    opsz ||= @size

    # addrsize override / segment override / rex_bx
    if mrm = i.args.grep(ModRM).first
      mrm.encode(0, @endianness) if mrm.b or mrm.i	# may reorder b/i, which must be correct for rex
      rex_b = 1 if mrm.b and mrm.b.val_rex.to_i > 0
      rex_x = 1 if mrm.i and mrm.i.val_rex.to_i > 0
      pfx << 0x67 if (mrm.b and mrm.b.sz == 32) or (mrm.i and mrm.i.sz == 32) or op.props[:adsz] == 32
      pfx << [0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65][mrm.seg.val] if mrm.seg
    elsif op.props[:adsz] == 32
      pfx << 0x67
    end


    #
    # encode embedded arguments
    #
    postponed = []
    oi.each { |oa, ia|
      case oa
      when :reg
        set_field[oa, ia.val_enc]
        if op.fields[:reg][1] == 3
          rex_r = ia.val_rex || 0
        else
          rex_b = ia.val_rex || 0
        end
      when :seg3, :seg3A, :seg2, :seg2A, :eeec, :eeed, :eeet, :regfp, :regmmx, :regxmm, :regymm
        set_field[oa, ia.val & 7]
        rex_r = 1 if ia.val > 7
        pfx << 0x66 if oa == :regmmx and op.props[:xmmx] and ia.sz == 128
      when :vexvreg, :vexvxmm, :vexvymm
        set_field[:vex_vvvv, ia.val ^ 0xf]
      when :imm_val1, :imm_val3, :reg_cl, :reg_eax, :reg_dx, :regfp0
        # implicit
      when :modrm, :modrmmmx, :modrmxmm, :modrmymm
        # postpone, but we must set rex now
        case ia
        when ModRM
          ia.encode(0, @endianness)	# could swap b/i
          rex_x = ia.i.val_rex || 0 if ia.i
          rex_b = ia.b.val_rex || 0 if ia.b
        when Reg
          rex_b = ia.val_rex || 0
        else
          rex_b = ia.val >> 3
        end
        postponed << [oa, ia]
      else
        postponed << [oa, ia]
      end
    }

    if !(op.args & [:modrm, :modrmmmx, :modrmxmm, :modrmymm]).empty?
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

    pfx << op.props[:needpfx] if op.props[:needpfx]

    if op.fields[:vex_r]
      set_field[:vex_r, rex_r ^ 1]
      set_field[:vex_x, rex_x ^ 1] if op.fields[:vex_x]
      set_field[:vex_b, rex_b ^ 1] if op.fields[:vex_b]
      set_field[:vex_w, rex_w] if op.fields[:vex_w]
    elsif rex_r + rex_x + rex_b + rex_w >= 1 or i.args.grep(Reg).find { |r| r.sz == 8 and r.val >= 4 and r.val < 8 }
      rex = 0x40
      rex |= 1 if rex_b == 1
      rex |= 2 if rex_x == 1
      rex |= 4 if rex_r == 1
      rex |= 8 if rex_w == 1
      pfx << rex
    end
    ret = EncodedData.new(pfx + base.pack('C*'))

    postponed.each { |oa, ia|
      case oa
      when :modrm, :modrmmmx, :modrmxmm, :modrmymm
        if ia.kind_of? ModRM
          ed = ia.encode(regval, @endianness)
          if ed.kind_of?(::Array)
            if ed.length > 1
              # we know that no opcode can have more than 1 modrm
              ary = []
              ed.each { |m| ary << (ret.dup << m) }
              ret = ary
              next
            else
              ed = ed.first
            end
          end
        else
          ed = ModRM.encode_reg(ia, regval)
        end
      when :mrm_imm; ed = ia.imm.encode("a#{op.props[:adsz] || 64}".to_sym, @endianness)
      when :i8, :u8, :i16, :u16, :i32, :u32, :i64, :u64; ed = ia.encode(oa, @endianness)
      when :i
        type = if opsz == 64
          if op.props[:imm64]
            :a64
          else
            if _ia = ia.reduce and _ia.kind_of?(Integer) and _ia > 0 and (_ia >> 63) == 1
              # handle 0xffffffff_ffffffff -> -1, which should fit in i32
              ia = Expression[_ia - (1 << 64)]
            end
            :i32
          end
        else
          "a#{opsz}".to_sym
        end
        ed = ia.encode(type, @endianness)
      when :i4xmm, :i4ymm
        ed = ia.val << 4	# u8
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
