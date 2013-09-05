#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/x86_64/opcodes'
require 'metasm/decode'

module Metasm
class X86_64
  class ModRM
    def self.decode(edata, byte, endianness, adsz, opsz, seg=nil, regclass=Reg, pfx={})
      m = (byte >> 6) & 3
      rm = byte & 7

      if m == 3
        rm |= 8 if pfx[:rex_b]
        return regclass.new(rm, opsz)
      end

      adsz ||= 64

      # mod 0/1/2 m 4 => sib
      # mod 0 m 5 => rip+imm
      # sib: i 4 => no index, b 5 => no base

      s = i = b = imm = nil
      if rm == 4
        sib = edata.get_byte.to_i

        ii = (sib >> 3) & 7
          ii |= 8 if pfx[:rex_x]
        if ii != 4
          s = 1 << ((sib >> 6) & 3)
          i = Reg.new(ii, adsz)
        end

        bb = sib & 7
        if bb == 5 and m == 0
          m = 2	# :i32 follows
        else
          bb |= 8 if pfx[:rex_b]
          b = Reg.new(bb, adsz)
        end
      elsif rm == 5 and m == 0
        b = Reg.new(16, adsz)
        m = 2	# :i32 follows
      else
        rm |= 8 if pfx[:rex_b]
        b = Reg.new(rm, adsz)
      end

      case m
      when 1; itype = :i8
      when 2; itype = :i32
      end
      imm = Expression[edata.decode_imm(itype, endianness)] if itype

      if imm and imm.reduce.kind_of? Integer and imm.reduce < -0x100_0000
        # probably a base address -> unsigned
        imm = Expression[imm.reduce & ((1 << adsz) - 1)]
      end

      new adsz, opsz, s, i, b, imm, seg
    end
  end

  def decode_prefix(instr, byte)
    x = super(instr, byte)
    if instr.prefix.delete :rex
      # rex ignored if not last
      instr.prefix.delete :rex_b
      instr.prefix.delete :rex_x
      instr.prefix.delete :rex_r
      instr.prefix.delete :rex_w
    end
    if byte & 0xf0 == 0x40
      x = instr.prefix[:rex] = byte
      instr.prefix[:rex_b] = 1 if byte & 1 > 0
      instr.prefix[:rex_x] = 1 if byte & 2 > 0
      instr.prefix[:rex_r] = 1 if byte & 4 > 0
      instr.prefix[:rex_w] = 1 if byte & 8 > 0
    end
    x
  end

  def decode_instr_op(edata, di)
    before_ptr = edata.ptr
    op = di.opcode
    di.instruction.opname = op.name
    bseq = edata.read(op.bin.length).unpack('C*')		# decode_findopcode ensures that data >= op.length
    pfx = di.instruction.prefix || {}

    field_val = lambda { |f|
      if fld = op.fields[f]
        (bseq[fld[0]] >> fld[1]) & @fields_mask[f]
      end
    }
    field_val_r = lambda { |f|
      v = field_val[f]
      v |= 8 if v and (op.fields[f][1] == 3 ? pfx[:rex_r] : pfx[:rex_b])	# gruick ?
      v
    }

    opsz = op.props[:argsz] || (pfx[:rex_w] ? 64 : (pfx[:opsz] ? 16 : (op.props[:auto64] ? 64 : 32)))
    adsz = pfx[:adsz] ? 32 : 64
    mmxsz = (op.props[:xmmx] && pfx[:opsz]) ? 128 : 64

    op.args.each { |a|
      di.instruction.args << case a
      when :reg;    Reg.new     field_val_r[a], opsz
      when :eeec;   CtrlReg.new field_val_r[a]
      when :eeed;   DbgReg.new  field_val_r[a]
      when :seg2, :seg2A, :seg3, :seg3A; SegReg.new field_val[a]
      when :regmmx; SimdReg.new field_val_r[a], mmxsz
      when :regxmm; SimdReg.new field_val_r[a], 128

      when :farptr; Farptr.decode edata, @endianness, opsz
      when :i8, :u8, :i16, :u16, :i32, :u32, :i64, :u64; Expression[edata.decode_imm(a, @endianness)]
      when :i		# 64bit constants are sign-extended from :i32
        type = (opsz == 64 ? op.props[:imm64] ? :a64 : :i32 : "#{op.props[:unsigned_imm] ? 'a' : 'i'}#{opsz}".to_sym )
 				v = edata.decode_imm(type, @endianness)
        v &= 0xffff_ffff_ffff_ffff if opsz == 64 and op.props[:unsigned_imm] and v.kind_of? Integer
        Expression[v]

      when :mrm_imm;  ModRM.new(adsz, opsz, nil, nil, nil, Expression[edata.decode_imm("a#{adsz}".to_sym, @endianness)], pfx[:seg])
      when :modrm, :modrmA; ModRM.decode edata, field_val[a], @endianness, adsz, opsz, pfx[:seg], Reg, pfx
      when :modrmmmx; ModRM.decode edata, field_val[:modrm], @endianness, adsz, mmxsz, pfx[:seg], SimdReg, pfx
      when :modrmxmm; ModRM.decode edata, field_val[:modrm], @endianness, adsz, 128, pfx[:seg], SimdReg, pfx

      when :regfp;  FpReg.new   field_val[a]
      when :imm_val1; Expression[1]
      when :imm_val3; Expression[3]
      when :reg_cl;   Reg.new 1, 8
      when :reg_eax;  Reg.new 0, opsz
      when :reg_dx;   Reg.new 2, 16
      when :regfp0;   FpReg.new nil
      else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
      end
    }

    di.bin_length += edata.ptr - before_ptr

    if op.name == 'movsx' or op.name == 'movzx' or op.name == 'movsxd'
      if op.name == 'movsxd'
        di.instruction.args[1].sz = 32
      elsif opsz == 8
        di.instruction.args[1].sz = 8
      else
        di.instruction.args[1].sz = 16
      end
      if pfx[:rex_w]
        di.instruction.args[0].sz = 64
      elsif pfx[:opsz]
        di.instruction.args[0].sz = 16
      else
        di.instruction.args[0].sz = 32
      end
    end

    # sil => bh
    di.instruction.args.each { |a| a.val += 12 if a.kind_of? Reg and a.sz == 8 and not pfx[:rex] and a.val >= 4 and a.val <= 8 }

    pfx.delete :seg
    case pfx.delete(:rep)
    when :nz
      if di.opcode.props[:strop]
        pfx[:rep] = 'rep'
      elsif di.opcode.props[:stropz]
        pfx[:rep] = 'repnz'
      end
    when :z
      if di.opcode.props[:strop]
        pfx[:rep] = 'rep'
      elsif di.opcode.props[:stropz]
        pfx[:rep] = 'repz'
      end
    end

    di
  end

  def decode_instr_interpret(di, addr)
    super(di, addr)

    # [rip + 42] => [rip - addr + foo]
    if m = di.instruction.args.grep(ModRM).first and
        ((m.b and m.b.val == 16) or (m.i and m.i.val == 16)) and
        m.imm and m.imm.reduce.kind_of?(Integer)
      m.imm = Expression[[:-, di.address + di.bin_length], :+, di.address+di.bin_length+m.imm.reduce]
    end

    di
  end

  def opsz(di)
    if di and di.instruction.prefix and di.instruction.prefix[:rex_w]; 64
    elsif di and di.instruction.prefix and di.instruction.prefix[:opsz]; 16
    elsif di and di.opcode.props[:auto64]; 64
    else 32
    end
  end

  def register_symbols
    [:rax, :rcx, :rdx, :rbx, :rsp, :rbp, :rsi, :rdi, :r8, :r9, :r10, :r11, :r12, :r13, :r14, :r15]
  end
  
  # returns a DecodedFunction from a parsed C function prototype
  def decode_c_function_prototype(cp, sym, orig=nil)
    sym = cp.toplevel.symbol[sym] if sym.kind_of?(::String)
    df = DecodedFunction.new
    orig ||= Expression[sym.name]

    new_bt = lambda { |expr, rlen|
      df.backtracked_for << BacktraceTrace.new(expr, orig, expr, rlen ? :r : :x, rlen)
    }

    # return instr emulation
    if sym.has_attribute 'noreturn' or sym.has_attribute '__noreturn__'
      df.noreturn = true
    else
      new_bt[Indirection[:rsp, @size/8, orig], nil]
    end

    # register dirty (MS standard ABI)
    [:rax, :rcx, :rdx, :r8, :r9, :r10, :r11].each { |r|
      df.backtrace_binding.update r => Expression::Unknown
    }

    if cp.lexer.definition['__MS_X86_64_ABI__']
      reg_args = [:rcx, :rdx, :r8, :r9]
    else
      reg_args = [:rdi, :rsi, :rdx, :rcx, :r8, :r9]
    end

    al = cp.typesize[:ptr]
      df.backtrace_binding[:rsp] = Expression[:rsp, :+, al]

    # scan args for function pointers
    # TODO walk structs/unions..
    stackoff = al
    sym.type.args.to_a.zip(reg_args).each { |a, r|
      if not r
        r = Indirection[[:rsp, :+, stackoff], al, orig]
        stackoff += (cp.sizeof(a) + al - 1) / al * al
      end
      if a.type.untypedef.kind_of? C::Pointer
        pt = a.type.untypedef.type.untypedef
        if pt.kind_of? C::Function
          new_bt[r, nil]
          df.backtracked_for.last.detached = true
        elsif pt.kind_of? C::Struct
          new_bt[r, al]
        else
          new_bt[r, cp.sizeof(nil, pt)]
        end
      end
    }

    df
  end

  def backtrace_update_function_binding_check(dasm, faddr, f, b)
    # TODO save regs according to ABI
  end
end
end
