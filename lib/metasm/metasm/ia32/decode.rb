#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/ia32/opcodes'
require 'metasm/decode'

module Metasm
class Ia32
  class ModRM
    def self.decode(edata, byte, endianness, adsz, opsz, seg=nil, regclass=Reg)
      m = (byte >> 6) & 3
      rm = byte & 7

      if m == 3
        return regclass.new(rm, opsz)
      end

      sum = Sum[adsz][m][rm]

      s, i, b, imm = nil
      sum.each { |a|
        case a
        when Integer
          if not b
            b = Reg.new(a, adsz)
          else
            s = 1
            i = Reg.new(a, adsz)
          end

        when :sib
          sib = edata.get_byte.to_i

          ii = ((sib >> 3) & 7)
          if ii != 4
            s = 1 << ((sib >> 6) & 3)
            i = Reg.new(ii, adsz)
          end

          bb = sib & 7
          if bb == 5 and m == 0
            imm = Expression[edata.decode_imm("i#{adsz}".to_sym, endianness)]
          else
            b = Reg.new(bb, adsz)
          end

        when :i8, :i16, :i32
          imm = Expression[edata.decode_imm(a, endianness)]
        end
      }

      if imm and imm.reduce.kind_of? Integer and imm.reduce < -0x10_0000
        # probably a base address -> unsigned
        imm = Expression[imm.reduce & ((1 << (adsz || 32)) - 1)]
      end

      new adsz, opsz, s, i, b, imm, seg
    end
  end

  class Farptr
    def self.decode(edata, endianness, adsz)
      addr = Expression[edata.decode_imm("u#{adsz}".to_sym, endianness)]
      seg = Expression[edata.decode_imm(:u16, endianness)]
      new seg, addr
    end
  end

  def build_opcode_bin_mask(op)
    # bit = 0 if can be mutated by an field value, 1 if fixed by opcode
    op.bin_mask = Array.new(op.bin.length, 0)
    op.fields.each { |f, (oct, off)|
      op.bin_mask[oct] |= (@fields_mask[f] << off)
    }
    op.bin_mask.map! { |v| 255 ^ v }
  end

  def build_bin_lookaside
    # sets up a hash byte value => list of opcodes that may match
    # opcode.bin_mask is built here
    lookaside = Array.new(256) { [] }
    opcode_list.each { |op|

      build_opcode_bin_mask op

      b   = op.bin[0]
      msk = op.bin_mask[0]

      for i in b..(b | (255^msk))
        next if i & msk != b & msk
        lookaside[i] << op
      end
    }
    lookaside
  end

  def decode_prefix(instr, byte)
    # XXX check multiple occurences ?
    instr.prefix ||= {}
    (instr.prefix[:list] ||= []) << byte

    case byte
    when 0x66; instr.prefix[:opsz] = true
    when 0x67; instr.prefix[:adsz] = true
    when 0xF0; instr.prefix[:lock] = true
    when 0xF2; instr.prefix[:rep]  = :nz
    when 0xF3; instr.prefix[:rep]  = :z	# postprocessed by decode_instr
    when 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65
      if byte & 0x40 == 0
        v = (byte >> 3) & 3
      else
        v = byte & 7
      end
      instr.prefix[:seg] = SegReg.new(v)

      instr.prefix[:jmphint] = ((byte & 0x10) == 0x10)
    else
      return false
    end
    true
  end

  # tries to find the opcode encoded at edata.ptr
  # if no match, tries to match a prefix (update di.instruction.prefix)
  # on match, edata.ptr points to the first byte of the opcode (after prefixes)
  def decode_findopcode(edata)
    di = DecodedInstruction.new self
    while edata.ptr < edata.data.length
      pfx = di.instruction.prefix || {}
      byte = edata.data[edata.ptr]
      byte = byte.unpack('C').first if byte.kind_of? ::String	# 1.9
      return di if di.opcode = @bin_lookaside[byte].find { |op|
        # fetch the relevant bytes from edata
        bseq = edata.data[edata.ptr, op.bin.length].unpack('C*')
        di.opcode = op if op.props[:opsz]	# needed by opsz(di)

        # check against full opcode mask
        op.bin.zip(bseq, op.bin_mask).all? { |b1, b2, m| b2 and ((b1 & m) == (b2 & m)) } and
        # check special cases
        !(
          # fail if any of those is true
          (fld = op.fields[:seg2A]  and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg2A] == 1) or
          (fld = op.fields[:seg3A]  and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg3A] < 4) or
          (fld = op.fields[:seg3A] || op.fields[:seg3] and (bseq[fld[0]] >> fld[1]) & @fields_mask[:seg3] > 5) or
          (fld = op.fields[:modrmA] and (bseq[fld[0]] >> fld[1]) & 0xC0 == 0xC0) or
          (sz = op.props[:opsz] and opsz(di) != sz) or
          (ndpfx = op.props[:needpfx] and not pfx[:list].to_a.include? ndpfx) or
          # return non-ambiguous opcode (eg push.i16 in 32bit mode) / sync with addop_post in opcode.rb
          (pfx[:opsz] and (op.args == [:i] or op.args == [:farptr] or op.name[0, 3] == 'ret') and not op.props[:opsz]) or
          (pfx[:adsz] and op.props[:adsz] and op.props[:adsz] == @size)
         )
      }

      break if not decode_prefix(di.instruction, edata.get_byte)
      di.bin_length += 1
    end
  end

  def decode_instr_op(edata, di)
    before_ptr = edata.ptr
    op = di.opcode
    di.instruction.opname = op.name
    bseq = edata.read(op.bin.length).unpack('C*')		# decode_findopcode ensures that data >= op.length
    pfx = di.instruction.prefix || {}

    case op.props[:needpfx]
    when 0x66; pfx.delete :opsz
    when 0x67; pfx.delete :adsz
    when 0xF2, 0xF3; pfx.delete :rep
    end

    field_val = lambda { |f|
      if fld = op.fields[f]
        (bseq[fld[0]] >> fld[1]) & @fields_mask[f]
      end
    }

    opsz = opsz(di)

    if pfx[:adsz]
      adsz = 48 - @size
    else
      adsz = @size
    end

      mmxsz = ((op.props[:xmmx] && pfx[:opsz]) ? 128 : 64)
    op.args.each { |a|
      di.instruction.args << case a
      when :reg;    Reg.new     field_val[a], opsz
      when :eeec;   CtrlReg.new field_val[a]
      when :eeed;   DbgReg.new  field_val[a]
      when :seg2, :seg2A, :seg3, :seg3A; SegReg.new field_val[a]
      when :regfp;  FpReg.new   field_val[a]
      when :regmmx; SimdReg.new field_val[a], mmxsz
      when :regxmm; SimdReg.new field_val[a], 128

      when :farptr; Farptr.decode edata, @endianness, opsz
      when :i8, :u8, :u16; Expression[edata.decode_imm(a, @endianness)]
      when :i; Expression[edata.decode_imm("#{op.props[:unsigned_imm] ? 'a' : 'i'}#{opsz}".to_sym, @endianness)]

      when :mrm_imm;  ModRM.decode edata, (adsz == 16 ? 6 : 5), @endianness, adsz, opsz, pfx[:seg]
      when :modrm, :modrmA; ModRM.decode edata, field_val[a], @endianness, adsz, opsz, pfx[:seg]
      when :modrmmmx; ModRM.decode edata, field_val[:modrm], @endianness, adsz, mmxsz, pfx[:seg], SimdReg
      when :modrmxmm; ModRM.decode edata, field_val[:modrm], @endianness, adsz, 128, pfx[:seg], SimdReg

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

    if op.name == 'movsx' or op.name == 'movzx'
      if di.opcode.props[:argsz] == 8
        di.instruction.args[1].sz = 8
      else
        di.instruction.args[1].sz = 16
      end
      if pfx[:opsz]
        di.instruction.args[0].sz = 48-@size
      else
        di.instruction.args[0].sz = @size
      end
    end

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

  # converts relative jump/call offsets to absolute addresses
  # adds the eip delta to the offset +off+ of the instruction (may be an Expression) + its bin_length
  # do not call twice on the same di !
  def decode_instr_interpret(di, addr)
    if di.opcode.props[:setip] and di.instruction.args.last.kind_of? Expression and di.instruction.opname[0, 3] != 'ret'
      delta = di.instruction.args.last.reduce
      arg = Expression[[addr, :+, di.bin_length], :+, delta].reduce
      di.instruction.args[-1] = Expression[arg]
    end

    di
  end

  # return the list of registers as symbols in the order used by pushad
  # for use in backtrace and stuff, for compatibility with x64
  # esp is [4]
  REG_SYMS = [:eax, :ecx, :edx, :ebx, :esp, :ebp, :esi, :edi]
  def register_symbols
    REG_SYMS
  end

  # interprets a condition code (in an opcode name) as an expression involving backtracked eflags
  # eflag_p is never computed, and this returns Expression::Unknown for this flag
  # ex: 'z' => Expression[:eflag_z]
  def decode_cc_to_expr(cc)
    case cc
    when 'o'; Expression[:eflag_o]
    when 'no'; Expression[:'!', :eflag_o]
    when 'b', 'nae', 'c'; Expression[:eflag_c]
    when 'nb', 'ae', 'nc'; Expression[:'!', :eflag_c]
    when 'z', 'e'; Expression[:eflag_z]
    when 'nz', 'ne'; Expression[:'!', :eflag_z]
    when 'be', 'na'; Expression[:eflag_c, :|, :eflag_z]
    when 'nbe', 'a'; Expression[:'!', [:eflag_c, :|, :eflag_z]]
    when 's'; Expression[:eflag_s]
    when 'ns'; Expression[:'!', :eflag_s]
    when 'p', 'pe'; Expression::Unknown
    when 'np', 'po'; Expression::Unknown
    when 'l', 'nge'; Expression[:eflag_s, :'!=', :eflag_o]
    when 'nl', 'ge'; Expression[:eflag_s, :==, :eflag_o]
    when 'le', 'ng'; Expression[[:eflag_s, :'!=', :eflag_o], :|, :eflag_z]
    when 'nle', 'g'; Expression[[:eflag_s, :==, :eflag_o], :&, :eflag_z]
    when 'ecxz'; Expression[:'!', register_symbols[1]]
    when 'cxz'; Expression[:'!', [register_symbols[1], :&, 0xffff]]
    end
  end

  # hash opcode_name => lambda { |dasm, di, *symbolic_args| instr_binding }
  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end
  def backtrace_binding=(b) @backtrace_binding = b end

  def opsz(di)
    ret = @size
    ret = di.opcode.props[:argsz] if di and di.opcode.props[:argsz]
    ret = 48 - ret if di and not di.opcode.props[:argsz] and di.instruction.prefix and di.instruction.prefix[:opsz]
    ret
  end

  # populate the @backtrace_binding hash with default values
  def init_backtrace_binding
    @backtrace_binding ||= {}

    eax, ecx, edx, ebx, esp, ebp, esi, edi = register_symbols

    mask = lambda { |di| (1 << opsz(di))-1 }	# 32bits => 0xffff_ffff
    sign = lambda { |v, di| Expression[[[v, :&, mask[di]], :>>, opsz(di)-1], :'!=', 0] }

    opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
      binding = case op
      when 'mov', 'movsx', 'movzx', 'movsxd', 'movd', 'movq'; lambda { |di, a0, a1| { a0 => Expression[a1] } }
      when 'lea'; lambda { |di, a0, a1| { a0 => a1.target } }
      when 'xchg'; lambda { |di, a0, a1| { a0 => Expression[a1], a1 => Expression[a0] } }
      when 'add', 'sub', 'or', 'xor', 'and', 'pxor', 'adc', 'sbb'
        lambda { |di, a0, a1|
          e_op = { 'add' => :+, 'sub' => :-, 'or' => :|, 'and' => :&, 'xor' => :^, 'pxor' => :^, 'adc' => :+, 'sbb' => :- }[op]
          ret = Expression[a0, e_op, a1]
          ret = Expression[ret, e_op, :eflag_c] if op == 'adc' or op == 'sbb'
          # optimises eax ^ eax => 0
          # avoid hiding memory accesses (to not hide possible fault)
          ret = Expression[ret.reduce] if not a0.kind_of? Indirection
          { a0 => ret }
        }
      when 'xadd'; lambda { |di, a0, a1| { a0 => Expression[a0, :+, a1], a1 => Expression[a0] } }
      when 'inc'; lambda { |di, a0| { a0 => Expression[a0, :+, 1] } }
      when 'dec'; lambda { |di, a0| { a0 => Expression[a0, :-, 1] } }
      when 'not'; lambda { |di, a0| { a0 => Expression[a0, :^, mask[di]] } }
      when 'neg'; lambda { |di, a0| { a0 => Expression[:-, a0] } }
      when 'rol', 'ror'
        lambda { |di, a0, a1|
          e_op = (op[2] == ?r ? :>> : :<<)
          inv_op = {:<< => :>>, :>> => :<< }[e_op]
          sz = [a1, :%, opsz(di)]
          isz = [[opsz(di), :-, a1], :%, opsz(di)]
          # ror a, b  =>  (a >> b) | (a << (32-b))
          { a0 => Expression[[[a0, e_op, sz], :|, [a0, inv_op, isz]], :&, mask[di]] }
        }
      when 'sar', 'shl', 'sal'; lambda { |di, a0, a1| { a0 => Expression[a0, (op[-1] == ?r ? :>> : :<<), [a1, :%, [opsz(di), 32].max]] } }
      when 'shr'; lambda { |di, a0, a1| { a0 => Expression[[a0, :&, mask[di]], :>>, [a1, :%, opsz(di)]] } }
      when 'cwd', 'cdq', 'cqo'; lambda { |di| { Expression[edx, :&, mask[di]] => Expression[mask[di], :*, sign[eax, di]] } }
      when 'cbw', 'cwde', 'cdqe'; lambda { |di|
        o2 = opsz(di)/2 ; m2 = (1 << o2) - 1
        { Expression[eax, :&, mask[di]] => Expression[[eax, :&, m2], :|, [m2 << o2, :*, [[eax, :>>, o2-1], :&, 1]]] } }
      when 'push'
        lambda { |di, a0| { esp => Expression[esp, :-, opsz(di)/8],
          Indirection[esp, opsz(di)/8, di.address] => Expression[a0] } }
      when 'pop'
        lambda { |di, a0| { esp => Expression[esp, :+, opsz(di)/8],
          a0 => Indirection[esp, opsz(di)/8, di.address] } }
      when 'pushfd'
        # TODO Unknown per bit
        lambda { |di|
          efl = Expression[0x202]
          bts = lambda { |pos, v| efl = Expression[efl, :|, [[v, :&, 1], :<<, pos]] }
          bts[0, :eflag_c]
          bts[6, :eflag_z]
          bts[7, :eflag_s]
          bts[11, :eflag_o]
          { esp => Expression[esp, :-, opsz(di)/8], Indirection[esp, opsz(di)/8, di.address] => efl }
               }
      when 'popfd'
        lambda { |di| bt = lambda { |pos| Expression[[Indirection[esp, opsz(di)/8, di.address], :>>, pos], :&, 1] }
          { esp => Expression[esp, :+, opsz(di)/8], :eflag_c => bt[0], :eflag_z => bt[6], :eflag_s => bt[7], :eflag_o => bt[11] } }
      when 'sahf'
        lambda { |di| bt = lambda { |pos| Expression[[eax, :>>, pos], :&, 1] }
          { :eflag_c => bt[0], :eflag_z => bt[6], :eflag_s => bt[7] } }
      when 'lahf'
        lambda { |di|
          efl = Expression[2]
          bts = lambda { |pos, v| efl = Expression[efl, :|, [[v, :&, 1], :<<, pos]] }
          bts[0, :eflag_c] #bts[2, :eflag_p] #bts[4, :eflag_a]
          bts[6, :eflag_z]
          bts[7, :eflag_s]
          { eax => efl }
        }
      when 'pushad'
        lambda { |di|
          ret = {}
          st_off = 0
          register_symbols.reverse_each { |r|
            ret[Indirection[Expression[esp, :+, st_off].reduce, opsz(di)/8, di.address]] = Expression[r]
            st_off += opsz(di)/8
          }
          ret[esp] = Expression[esp, :-, st_off]
          ret
        }
      when 'popad'
        lambda { |di|
          ret = {}
          st_off = 0
          register_symbols.reverse_each { |r|
            ret[r] = Indirection[Expression[esp, :+, st_off].reduce, opsz(di)/8, di.address]
            st_off += opsz(di)/8
          }
          ret[esp] = Expression[esp, :+, st_off]	# esp is not popped
          ret
        }
      when 'call'
        lambda { |di, a0| { esp => Expression[esp, :-, opsz(di)/8],
          Indirection[esp, opsz(di)/8, di.address] => Expression[di.next_addr] } }
      when 'ret'; lambda { |di, *a| { esp => Expression[esp, :+, [opsz(di)/8, :+, a[0] || 0]] } }
      when 'loop', 'loopz', 'loopnz'; lambda { |di, a0| { ecx => Expression[ecx, :-, 1] } }
      when 'enter'
        lambda { |di, a0, a1|
          sz = opsz(di)/8
          depth = a1.reduce % 32
          b = {	Indirection[ebp, sz, di.address] => Expression[ebp],
            Indirection[[esp, :+, a0.reduce+sz*depth], sz, di.address] => Expression[ebp],
            ebp => Expression[esp, :-, sz],
            esp => Expression[esp, :-, a0.reduce+sz*depth+sz] }
          (1..depth).each { |i|
            b[Indirection[[esp, :+, a0.reduce+i*sz], sz, di.address]] =
            b[Indirection[[ebp, :-, i*sz], sz, di.address]] =
                     Expression::Unknown # TODO Indirection[[ebp, :-, i*sz], sz, di.address]
          }
          b
        }
      when 'leave'; lambda { |di| { ebp => Indirection[[ebp], opsz(di)/8, di.address], esp => Expression[ebp, :+, opsz(di)/8] } }
      when 'aaa'; lambda { |di| { eax => Expression::Unknown, :incomplete_binding => Expression[1] } }
      when 'imul'
        lambda { |di, *a|
          # 1 operand form == same as 'mul' (ax:dx stuff)
          next { eax => Expression::Unknown, edx => Expression::Unknown, :incomplete_binding => Expression[1] } if not a[1]

          if a[2]; e = Expression[a[1], :*, a[2]]
          else e = Expression[[a[0], :*, a[1]], :&, (1 << (di.instruction.args.first.sz || opsz(di))) - 1]
          end
          { a[0] => e }
        }
      when 'mul', 'div', 'idiv'; lambda { |di, *a| { eax => Expression::Unknown, edx => Expression::Unknown, :incomplete_binding => Expression[1] } }
      when 'rdtsc'; lambda { |di| { eax => Expression::Unknown, edx => Expression::Unknown, :incomplete_binding => Expression[1] } }
      when /^(stos|movs|lods|scas|cmps)[bwd]$/
        lambda { |di|
          op =~ /^(stos|movs|lods|scas|cmps)([bwd])$/
          e_op = $1
          sz = { 'b' => 1, 'w' => 2, 'd' => 4 }[$2]
          eax_ = Reg.new(0, 8*sz).symbolic
          dir = :+
          if di.block and (di.block.list.find { |ddi| ddi.opcode.name == 'std' } rescue nil)
            dir = :-
          end
          pesi = Indirection[esi, sz, di.address]
          pedi = Indirection[edi, sz, di.address]
          pfx = di.instruction.prefix || {}
          bd =
          case e_op
          when 'movs'
            case pfx[:rep]
            when nil; { pedi => pesi, esi => Expression[esi, dir, sz], edi => Expression[edi, dir, sz] }
            else      { pedi => pesi, esi => Expression[esi, dir, [sz ,:*, ecx]], edi => Expression[edi, dir, [sz, :*, ecx]], ecx => 0 }
            end
          when 'stos'
            case pfx[:rep]
            when nil; { pedi => Expression[eax_], edi => Expression[edi, dir, sz] }
            else      { pedi => Expression[eax_], edi => Expression[edi, dir, [sz, :*, ecx]], ecx => 0 }
            end
          when 'lods'
            case pfx[:rep]
            when nil; { eax_ => pesi, esi => Expression[esi, dir, sz] }
            else      { eax_ => Indirection[[esi, dir, [sz, :*, [ecx, :-, 1]]], sz, di.address], esi => Expression[esi, dir, [sz, :*, ecx]], ecx => 0 }
            end
          when 'scas'
            case pfx[:rep]
            when nil; { edi => Expression[edi, dir, sz] }
            else { edi => Expression::Unknown, ecx => Expression::Unknown }
            end
          when 'cmps'
            case pfx[:rep]
            when nil; { edi => Expression[edi, dir, sz], esi => Expression[esi, dir, sz] }
            else { edi => Expression::Unknown, esi => Expression::Unknown, ecx => Expression::Unknown }
            end
          end
          bd[:incomplete_binding] = Expression[1] if pfx[:rep]
          bd
        }
      when 'clc'; lambda { |di| { :eflag_c => Expression[0] } }
      when 'stc'; lambda { |di| { :eflag_c => Expression[1] } }
      when 'cmc'; lambda { |di| { :eflag_c => Expression[:'!', :eflag_c] } }
      when 'cld'; lambda { |di| { :eflag_d => Expression[0] } }
      when 'std'; lambda { |di| { :eflag_d => Expression[1] } }
      when 'setalc'; lambda { |di| { Reg.new(0, 8).symbolic => Expression[:eflag_c, :*, 0xff] } }
      when /^set/; lambda { |di, *a| { a[0] => Expression[decode_cc_to_expr(op[/^set(.*)/, 1])] } }
      when /^cmov/; lambda { |di, *a| fl = decode_cc_to_expr(op[/^cmov(.*)/, 1]) ; { a[0] => Expression[[fl, :*, a[1]], :|, [[1, :-, fl], :*, a[0]]] } }
      when /^j/
        lambda { |di, a0|
          ret = { 'dummy_metasm_0' => Expression[a0] }	# mark modr/m as read
          if fl = decode_cc_to_expr(op[/^j(.*)/, 1]) and fl != Expression::Unknown
            ret['dummy_metasm_1'] = fl	# mark eflags as read
          end
          ret
        }
      when 'fstenv', 'fnstenv'
               lambda { |di, a0|
          # stores the address of the last non-control fpu instr run
          lastfpuinstr = di.block.list[0...di.block.list.index(di)].reverse.find { |pdi|
            case pdi.opcode.name
            when /fn?init|fn?clex|fldcw|fn?st[cs]w|fn?stenv|fldenv|fn?save|frstor|f?wait/
            when /^f/; true
            end
          } if di.block
          lastfpuinstr = lastfpuinstr.address if lastfpuinstr
          ret = {}
          save_at = lambda { |off, val| ret[Indirection[a0.target + off, 4, di.address]] = val }
          save_at[0, Expression::Unknown]
          save_at[4, Expression::Unknown]
          save_at[8, Expression::Unknown]
          save_at[12, lastfpuinstr || Expression::Unknown]
          save_at[16, Expression::Unknown]
          save_at[20, Expression::Unknown]
          save_at[24, Expression::Unknown]
          ret
        }
      when 'bt';  lambda { |di, a0, a1| { :eflag_c => Expression[[a0, :>>, [a1, :%, opsz(di)]], :&, 1] } }
      when 'bts'; lambda { |di, a0, a1| { :eflag_c => Expression[[a0, :>>, [a1, :%, opsz(di)]], :&, 1],
        a0 => Expression[a0, :|, [1, :<<, [a1, :%, opsz(di)]]] } }
      when 'btr'; lambda { |di, a0, a1| { :eflag_c => Expression[[a0, :>>, [a1, :%, opsz(di)]], :&, 1],
        a0 => Expression[a0, :&, [[1, :<<, [a1, :%, opsz(di)]], :^, mask[di]]] } }
      when 'btc'; lambda { |di, a0, a1| { :eflag_c => Expression[[a0, :>>, [a1, :%, opsz(di)]], :&, 1],
        a0 => Expression[a0, :^, [1, :<<, [a1, :%, opsz(di)]]] } }
      when 'bswap'
        lambda { |di, a0|
          if opsz(di) == 64
            { a0 => Expression[
              [[[[a0, :&, 0xff000000_00000000], :>>, 56],   :|,
                [[a0, :&, 0x00ff0000_00000000], :>>, 40]],  :|,
               [[[a0, :&, 0x0000ff00_00000000], :>>, 24],   :|,
                [[a0, :&, 0x000000ff_00000000], :>>,  8]]], :|,
              [[[[a0, :&, 0x00000000_ff000000], :<<,  8],   :|,
                [[a0, :&, 0x00000000_00ff0000], :<<, 24]],  :|,
               [[[a0, :&, 0x00000000_0000ff00], :<<, 40],   :|,
                [[a0, :&, 0x00000000_000000ff], :<<, 56]]]] }
          else	# XXX opsz != 32 => undef
            { a0 => Expression[
              [[[a0, :&, 0xff000000], :>>, 24],  :|,
               [[a0, :&, 0x00ff0000], :>>,  8]], :|,
              [[[a0, :&, 0x0000ff00], :<<,  8],  :|,
               [[a0, :&, 0x000000ff], :<<, 24]]] }
          end
        }
      when 'nop', 'pause', 'wait', 'cmp', 'test'; lambda { |di, *a| {} }
      end

      # add eflags side-effects

      full_binding = case op
      when 'adc', 'add', 'and', 'cmp', 'or', 'sbb', 'sub', 'xor', 'test', 'xadd'
        lambda { |di, a0, a1|
          e_op = { 'adc' => :+, 'add' => :+, 'xadd' => :+, 'and' => :&, 'cmp' => :-, 'or' => :|, 'sbb' => :-, 'sub' => :-, 'xor' => :^, 'test' => :& }[op]
          res = Expression[[a0, :&, mask[di]], e_op, [a1, :&, mask[di]]]
          res = Expression[res, e_op, :eflag_c] if op == 'adc' or op == 'sbb'

          ret = (binding ? binding[di, a0, a1] : {})
          ret[:eflag_z] = Expression[[res, :&, mask[di]], :==, 0]
          ret[:eflag_s] = sign[res, di]
          ret[:eflag_c] = case e_op
            when :+; Expression[res, :>, mask[di]]
            when :-; Expression[[a0, :&, mask[di]], :<, [a1, :&, mask[di]]]
            else Expression[0]
            end
          ret[:eflag_o] = case e_op
            when :+; Expression[[sign[a0, di], :==, sign[a1, di]], :'&&', [sign[a0, di], :'!=', sign[res, di]]]
            when :-; Expression[[sign[a0, di], :==, [:'!', sign[a1, di]]], :'&&', [sign[a0, di], :'!=', sign[res, di]]]
            else Expression[0]
            end
          ret
        }
      when 'inc', 'dec', 'neg', 'shl', 'shr', 'sar', 'ror', 'rol', 'rcr', 'rcl', 'shld', 'shrd'
        lambda { |di, a0, *a|
          ret = (binding ? binding[di, a0, *a] : {})
          res = ret[a0] || Expression::Unknown
          ret[:eflag_z] = Expression[[res, :&, mask[di]], :==, 0]
          ret[:eflag_s] = sign[res, di]
          case op
          when 'neg'; ret[:eflag_c] = Expression[[res, :&, mask[di]], :'!=', 0]
          when 'inc', 'dec'	# don't touch carry flag
          else ret[:eflag_c] = Expression::Unknown	# :incomplete_binding ?
          end
          ret[:eflag_o] = case op
          when 'inc'; Expression[[a0, :&, mask[di]], :==, mask[di] >> 1]
          when 'dec'; Expression[[res , :&, mask[di]], :==, mask[di] >> 1]
          when 'neg'; Expression[[a0, :&, mask[di]], :==, (mask[di]+1) >> 1]
          else Expression::Unknown
          end
          ret
        }
      when 'imul', 'mul', 'idiv', 'div', /^(scas|cmps)[bwdq]$/
        lambda { |di, *a|
          ret = (binding ? binding[di, *a] : {})
          ret[:eflag_z] = ret[:eflag_s] = ret[:eflag_c] = ret[:eflag_o] = Expression::Unknown	# :incomplete_binding ?
          ret
        }
      end

      @backtrace_binding[op] ||= full_binding || binding if full_binding || binding
    }
    @backtrace_binding
  end

  # returns the condition (bool Expression) under which a conditionnal jump is taken
  # returns nil if not a conditionnal jump
  # backtrace for the condition must include the jump itself (eg loop -> ecx--)
  def get_jump_condition(di)
    ecx = register_symbols[1]
    case di.opcode.name
    when /^j(.*)/
      decode_cc_to_expr($1)
    when /^loop(.+)?/
      e = Expression[ecx, :'!=', 0]
      e = Expression[e, :'||', decode_cc_to_expr($1)] if $1
      e
    end
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when ModRM, Reg, SimdReg; arg.symbolic(di)
      else arg
      end
    }

    if binding = backtrace_binding[di.opcode.basename]
      bd = binding[di, *a]
      # handle modifications to al/ah etc
      bd.keys.grep(Expression).each { |e|
        # must be in the form (x & mask), with x either :reg or (:reg >> shift) eg ah == ((eax >> 8) & 0xff)
        if e.op == :& and mask = e.rexpr and mask.kind_of? Integer
          reg = e.lexpr
          reg = reg.lexpr if reg.kind_of? Expression and reg.op == :>> and shift = reg.rexpr and shift.kind_of? Integer
          next if not reg.kind_of? Symbol
          if bd.has_key? reg
            # xchg ah, al ; pop sp..
            puts "backtrace: conflict for #{di}: #{e} vs #{reg}" if $VERBOSE
            bd[reg] = Expression::Unknown
            next
          end
          val = bd.delete e
          mask <<= shift if shift
          invmask = mask ^ (@size == 64 ? 0xffff_ffff_ffff_ffff : 0xffff_ffff)
          if invmask == 0xffff_ffff_0000_0000 and not di.opcode.props[:op32no64]
            bd[reg] = Expression[val, :&, 0xffff_ffff]
          elsif invmask == 0
            bd[reg] = val
          else
            val = Expression[val, :<<, shift] if shift
            bd[reg] = Expression[[reg, :&, invmask], :|, [val, :&, mask]]
          end
        end
      }
      bd
    else
      puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
      # assume nothing except the 1st arg is modified
      case a[0]
      when Indirection, Symbol; { a[0] => Expression::Unknown }
      when Expression; (x = a[0].externals.first) ? { x => Expression::Unknown } : {}
      else {}
      end.update(:incomplete_binding => Expression[1])
    end
  end

  def get_xrefs_x(dasm, di)
    return [] if not di.opcode.props[:setip]

    sz = opsz(di)
    case di.opcode.basename
    when 'ret'; return [Indirection[register_symbols[4], sz/8, di.address]]
    when 'jmp', 'call'
      a = di.instruction.args.first
      if dasm and a.kind_of?(ModRM) and a.imm and a.s == sz/8 and not a.b and dasm.get_section_at(a.imm)
        return get_xrefs_x_jmptable(dasm, di, a, sz)
      end
    end

    case tg = di.instruction.args.first
    when ModRM
      tg.sz ||= sz if tg.kind_of? ModRM
      [Expression[tg.symbolic(di)]]
    when Reg; [Expression[tg.symbolic(di)]]
    when Expression, ::Integer; [Expression[tg]]
    when Farptr; tg.seg.reduce < 0x30 ? [tg.addr] : [Expression[[tg.seg, :*, 0x10], :+, tg.addr]]
    else
      puts "unhandled setip at #{di.address} #{di.instruction}" if $DEBUG
      []
    end
  end

  # we detected a jmp table (jmp [base+4*idx])
  # try to return an accurate dest list
  def get_xrefs_x_jmptable(dasm, di, mrm, sz)
    # include the symbolic dest for backtrack stuff
    ret = [Expression[mrm.symbolic(di)]]
    i = mrm.i
    if di.block.list.length == 2 and di.block.list[0].opcode.name =~ /^mov/ and a0 = di.block.list[0].instruction.args[0] and
        a0.respond_to? :symbolic and a0.symbolic == i.symbolic
      i = di.block.list[0].instruction.args[1]
    end
    pb = di.block.from_normal.to_a
    if pb.length == 1 and pdi = dasm.decoded[pb[0]] and pdi.opcode.name =~ /^jn?be?/ and ppdi = pdi.block.list[-2] and ppdi.opcode.name == 'cmp' and
        ppdi.instruction.args[0].symbolic == i.symbolic and lim = Expression[ppdi.instruction.args[1]].reduce and lim.kind_of? Integer
      # cmp eax, 42 ; jbe switch ; switch: jmp [base+4*eax]
      s = dasm.get_section_at(mrm.imm)
      lim += 1 if pdi.opcode.name[-1] == ?e
      lim.times { |v|
        dasm.add_xref(s[1]+s[0].ptr, Xref.new(:r, di.address, sz/8))
        ret << Indirection[[mrm.imm, :+, v*sz/8], sz/8, di.address]
        s[0].read(sz/8)
      }
      l = dasm.auto_label_at(mrm.imm, 'jmp_table', 'xref')
      replace_instr_arg_immediate(di.instruction, mrm.imm, Expression[l])
      return ret
    end

    puts "unrecognized jmp table pattern, using wild guess for #{di}" if $VERBOSE
    di.add_comment 'wildguess'
    if s = dasm.get_section_at(mrm.imm - 3*sz/8)
      v = -3
    else
      s = dasm.get_section_at(mrm.imm)
      v = 0
    end
    loop do
      ptr = dasm.normalize s[0].decode_imm("u#{sz}".to_sym, @endianness)
      diff = Expression[ptr, :-, di.address].reduce
      if (diff.kind_of? ::Integer and diff.abs < 4096) or (di.opcode.basename == 'call' and ptr != 0 and dasm.get_section_at(ptr))
        dasm.add_xref(s[1]+s[0].ptr-sz/8, Xref.new(:r, di.address, sz/8))
        ret << Indirection[[mrm.imm, :+, v*sz/8], sz/8, di.address]
      elsif v > 0
        break
      end
      v += 1
    end
    ret
  end

  # checks if expr is a valid return expression matching the :saveip instruction
  def backtrace_is_function_return(expr, di=nil)
    expr = Expression[expr].reduce_rec
    expr.kind_of? Indirection and expr.len == @size/8 and expr.target == Expression[register_symbols[4]]
  end

  # updates the function backtrace_binding
  # if the function is big and no specific register is given, do nothing (the binding will be lazily updated later, on demand)
  # XXX assume retaddrlist is either a list of addr of ret or a list with a single entry which is an external function name (thunk)
  def backtrace_update_function_binding(dasm, faddr, f, retaddrlist, *wantregs)
    b = f.backtrace_binding

    esp, ebp = register_symbols[4, 2]

    # XXX handle retaddrlist for multiple/mixed thunks
    if retaddrlist and not dasm.decoded[retaddrlist.first] and di = dasm.decoded[faddr]
      # no return instruction, must be a thunk : find the last instruction (to backtrace from it)
      done = []
      while ndi = dasm.decoded[di.block.to_subfuncret.to_a.first] || dasm.decoded[di.block.to_normal.to_a.first] and ndi.kind_of? DecodedInstruction and not done.include? ndi.address
        done << ndi.address
        di = ndi
      end
      if not di.block.to_subfuncret.to_a.first and di.block.to_normal and di.block.to_normal.length > 1
        thunklast = di.block.list.last.address
      end
    end

    bt_val = lambda { |r|
      next if not retaddrlist
      b[r] = Expression::Unknown	# TODO :pending or something ? (for recursive lazy functions)
      bt = []
      retaddrlist.each { |retaddr|
        bt |= dasm.backtrace(Expression[r], (thunklast ? thunklast : retaddr),
          :include_start => true, :snapshot_addr => faddr, :origin => retaddr, :from_subfuncret => thunklast)
      }
      if bt.length != 1
        b[r] = Expression::Unknown
      else
        b[r] = bt.first
      end
    }

    if not wantregs.empty?
      wantregs.each(&bt_val)
    else
      if dasm.function_blocks(faddr, true).length < 20
        register_symbols.each(&bt_val)
      else
        [ebp, esp].each(&bt_val)
      end
    end

    backtrace_update_function_binding_check(dasm, faddr, f, b, &bt_val)

    b
  end

  def backtrace_update_function_binding_check(dasm, faddr, f, b)
    sz = @size/8
    if b[:ebp] and b[:ebp] != Expression[:ebp]
      # may be a custom 'enter' function (eg recent Visual Studio)
      # TODO put all memory writes in the binding ?
      [[:ebp], [:esp, :+, 1*sz], [:esp, :+, 2*sz], [:esp, :+, 3*sz]].each { |ptr|
        ind = Indirection[ptr, sz, faddr]
        yield(ind)
        b.delete(ind) if b[ind] and not [:ebx, :edx, :esi, :edi, :ebp].include? b[ind].reduce_rec
      }
    end
    if dasm.funcs_stdabi
      if b[:esp] and b[:esp] == Expression::Unknown and not f.btbind_callback
        puts "update_func_bind: #{Expression[faddr]} has esp -> unknown, use dynamic callback" if $DEBUG
        f.btbind_callback = disassembler_default_btbind_callback
      end
      [:ebp, :ebx, :esi, :edi].each { |reg|
        if b[reg] and b[reg] == Expression::Unknown
          puts "update_func_bind: #{Expression[faddr]} has #{reg} -> unknown, presume it is preserved" if $DEBUG
          b[reg] = Expression[reg]
        end
      }
    else
      if b[:esp] and not Expression[b[:esp], :-, :esp].reduce.kind_of?(::Integer)
        puts "update_func_bind: #{Expression[faddr]} has esp -> #{b[:esp]}" if $DEBUG
      end
    end

    # rename some functions
    # TODO database and real signatures
    rename =
    if b[:eax] and Expression[b[:eax], :-, faddr].reduce == 0
      'geteip' # metasm pic linker
    elsif b[:eax] and b[:ebx] and  Expression[b[:eax], :-, :eax].reduce == 0 and Expression[b[:ebx], :-, Indirection[:esp, sz, nil]].reduce == 0
      'get_pc_thunk_ebx' # elf pic convention
    elsif b[:esp] and Expression[b[:esp], :-, [:esp, :-, Indirection[[:esp, :+, 2*sz], sz]]].reduce.kind_of? ::Integer and
        dasm.decoded[faddr].block.list.find { |di| di.backtrace_binding[Indirection['segment_base_fs', sz]] }
      '__SEH_prolog'
    elsif b[:esp] == Expression[:ebp, :+, sz] and
        dasm.decoded[faddr].block.list.find { |di| di.backtrace_binding[Indirection['segment_base_fs', sz]] }
      '__SEH_epilog'
    end
    dasm.auto_label_at(faddr, rename, 'loc', 'sub') if rename
  end

  # returns true if the expression is an address on the stack
  def backtrace_is_stack_address(expr)
    Expression[expr].expr_externals.include? register_symbols[4]
  end

  # updates an instruction's argument replacing an expression with another (eg label renamed)
  def replace_instr_arg_immediate(i, old, new)
    i.args.map! { |a|
      case a
      when Expression; a == old ? new : Expression[a.bind(old => new).reduce]
      when ModRM
        a.imm = (a.imm == old ? new : Expression[a.imm.bind(old => new).reduce]) if a.imm
        a
      else a
      end
    }
  end

  # returns a DecodedFunction from a parsed C function prototype
  # TODO rebacktrace already decoded functions (load a header file after dasm finished)
  # TODO walk structs args
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
      new_bt[Indirection[:esp, @size/8, orig], nil]
    end

    # register dirty (XXX assume standard ABI)
    [:eax, :ecx, :edx].each { |r|
      df.backtrace_binding.update r => Expression::Unknown
    }

    # emulate ret <n>
    al = cp.typesize[:ptr]
    stackoff = al
    if sym.has_attribute 'fastcall'
      stackoff = sym.type.args.to_a[2..-1].to_a.inject(al) { |sum, a| sum += (cp.sizeof(a) + al - 1) / al * al }
    elsif sym.has_attribute 'stdcall'
      stackoff = sym.type.args.to_a.inject(al) { |sum, a| sum += (cp.sizeof(a) + al - 1) / al * al }
    end
    df.backtrace_binding[:esp] = Expression[:esp, :+, stackoff]

    # scan args for function pointers
    # TODO walk structs/unions..
    stackoff = al
    sym.type.args.to_a.each { |a|
      p = Indirection[[:esp, :+, stackoff], al, orig]
      stackoff += (cp.sizeof(a) + al - 1) / al * al
      if a.type.untypedef.kind_of? C::Pointer
        pt = a.type.untypedef.type.untypedef
        if pt.kind_of? C::Function
          new_bt[p, nil]
          df.backtracked_for.last.detached = true
        elsif pt.kind_of? C::Struct
          new_bt[p, al]
        else
          new_bt[p, cp.sizeof(nil, pt)]
        end
      end
    }

    df
  end

  # the lambda for the :default backtrace_binding callback of the disassembler
  # tries to determine the stack offset of unprototyped functions
  # working:
  #   checks that origin is a ret, that expr is an indirection from esp and that expr.origin is the ret
  #   bt_walk from calladdr until we finds a call into us, and assumes it is the current function start
  #   TODO handle foo: call bar ; bar: pop eax ; call <withourcallback> ; ret -> bar is not the function start (foo is)
  #   then backtrace expr from calladdr to funcstart (snapshot), using esp -> esp+<stackoffvariable>
  #   from the result, compute stackoffvariable (only if trivial)
  # will not work if the current function calls any other unknown function (unless all are __cdecl)
  # will not work if the current function is framed (ebp leave ret): in this case the function will return, but its esp will be unknown
  # if the stack offset is found and funcaddr is a string, fixup the static binding and remove the dynamic binding
  # TODO dynamise thunks bt_for & bt_cb
  def disassembler_default_btbind_callback
    esp = register_symbols[4]

    lambda { |dasm, bind, funcaddr, calladdr, expr, origin, maxdepth|
      @dasm_func_default_off ||= {}
      if off = @dasm_func_default_off[[dasm, calladdr]]
        bind = bind.merge(esp => Expression[esp, :+, off])
        break bind
      end
      break bind if not odi = dasm.decoded[origin] or odi.opcode.basename != 'ret'
      expr = expr.reduce_rec if expr.kind_of? Expression
      break bind unless expr.kind_of? Indirection and expr.origin == origin
      break bind unless expr.externals.reject { |e| e =~ /^autostackoffset_/ } == [esp]

      curfunc = dasm.function[funcaddr]
      if curfunc.backtrace_binding and tk = curfunc.backtrace_binding[:thunk] and dasm.function[tk]
        curfunc = dasm.function[tk]
      end

      # scan from calladdr for the probable parent function start
      func_start = nil
      dasm.backtrace_walk(true, calladdr, false, false, nil, maxdepth) { |ev, foo, h|
        if ev == :up and h[:sfret] != :subfuncret and di = dasm.decoded[h[:to]] and di.opcode.basename == 'call'
          func_start = h[:from]
          break
        elsif ev == :end
          # entrypoints are functions too
          func_start = h[:addr]
          break
        end
      }
      break bind if not func_start
      puts "automagic #{Expression[funcaddr]}: found func start for #{dasm.decoded[origin]} at #{Expression[func_start]}" if dasm.debug_backtrace
      s_off = "autostackoffset_#{Expression[funcaddr]}_#{Expression[calladdr]}"
      list = dasm.backtrace(expr.bind(esp => Expression[esp, :+, s_off]), calladdr, :include_start => true, :snapshot_addr => func_start, :maxdepth => maxdepth, :origin => origin)
      # check if this backtrace made us find our binding
      if off = @dasm_func_default_off[[dasm, calladdr]]
        bind = bind.merge(esp => Expression[esp, :+, off])
        break bind
      elsif not curfunc.btbind_callback
        break curfunc.backtrace_binding
      end
      e_expr = list.find { |e_expr_|
        # TODO cleanup this
        e_expr_ = Expression[e_expr_].reduce_rec
        next if not e_expr_.kind_of? Indirection
        off = Expression[[esp, :+, s_off], :-, e_expr_.target].reduce
        off.kind_of? Integer and off >= @size/8 and off < 10*@size/8 and (off % (@size/8)) == 0
      } || list.first

      e_expr = e_expr.rexpr if e_expr.kind_of? Expression and e_expr.op == :+ and not e_expr.lexpr
      break bind unless e_expr.kind_of? Indirection

      off = Expression[[esp, :+, s_off], :-, e_expr.target].reduce
      if off.kind_of? Expression
        bd = off.externals.grep(/^autostackoffset_/).inject({}) { |bd_, xt| bd_.update xt => @size/8 }
        bd.delete s_off
        if off.bind(bd).reduce == @size/8
          # all __cdecl
          off = @size/8
        else
          # check if all calls are to the same extern func
          bd.delete_if { |k, v| k !~ /^autostackoffset_#{Expression[funcaddr]}_/ }
          bd.each_key { |k| bd[k] = 0 }
          if off.bind(bd).reduce.kind_of? Integer
            off = off.bind(bd).reduce / (bd.length + 1)
          end
        end
      end
      if off.kind_of? Integer
        if off < @size/8 or off > 20*@size/8 or (off % (@size/8)) != 0
          puts "autostackoffset: ignoring off #{off} for #{Expression[funcaddr]} from #{dasm.decoded[calladdr]}" if $VERBOSE
          off = :unknown
        end
      end

      bind = bind.merge esp => Expression[esp, :+, off] if off != :unknown
      if funcaddr != :default
        if not off.kind_of? ::Integer
          #XXX we allow the current function to return, so we should handle the func backtracking its esp
          #(and other register that are saved and restored in epilog)
          puts "stackoff #{dasm.decoded[calladdr]} | #{Expression[func_start]} | #{expr} | #{e_expr} | #{off}" if dasm.debug_backtrace
        else
          puts "autostackoffset: found #{off} for #{Expression[funcaddr]} from #{dasm.decoded[calladdr]}" if $VERBOSE
          curfunc.btbind_callback = nil
          curfunc.backtrace_binding = bind

          # rebacktrace the return address, so that other unknown funcs that depend on us are solved
          dasm.backtrace(Indirection[esp, @size/8, origin], origin, :origin => origin)
        end
      else
        if off.kind_of? ::Integer and dasm.decoded[calladdr]
          puts "autostackoffset: found #{off-@size/8} for #{dasm.decoded[calladdr]}" if $VERBOSE
          di = dasm.decoded[calladdr]
          di.comment.delete_if { |c| c =~ /^stackoff=/ } if di.comment
          di.add_comment "stackoff=#{off-@size/8}"
          @dasm_func_default_off[[dasm, calladdr]] = off

          dasm.backtrace(Indirection[esp, @size/8, origin], origin, :origin => origin)
        elsif cachedoff = @dasm_func_default_off[[dasm, calladdr]]
          bind[esp] = Expression[esp, :+, cachedoff]
        elsif off.kind_of? ::Integer
          dasm.decoded[calladdr].add_comment "stackoff=#{off-@size/8}"
        end

        puts "stackoff #{dasm.decoded[calladdr]} | #{Expression[func_start]} | #{expr} | #{e_expr} | #{off}" if dasm.debug_backtrace
      end

      bind
    }
  end

  # the :default backtracked_for callback
  # returns empty unless funcaddr is not default or calladdr is a call or a jmp
  def disassembler_default_btfor_callback
    lambda { |dasm, btfor, funcaddr, calladdr|
      if funcaddr != :default; btfor
      elsif di = dasm.decoded[calladdr] and (di.opcode.name == 'call' or di.opcode.name == 'jmp'); btfor
      else []
      end
    }
  end

  # returns a DecodedFunction suitable for :default
  # uses disassembler_default_bt{for/bind}_callback
  def disassembler_default_func
    esp = register_symbols[4]
    cp = new_cparser
    cp.parse 'void stdfunc(void);'
    f = decode_c_function_prototype(cp, 'stdfunc', :default)
    f.backtrace_binding[esp] = Expression[esp, :+, :unknown]
    f.btbind_callback = disassembler_default_btbind_callback
    f.btfor_callback  = disassembler_default_btfor_callback
    f
  end

  # returns a hash { :retval => r, :changed => [] }
  def abi_funcall
    { :retval => register_symbols[0], :changed => register_symbols[0, 3] }
  end


  # computes the binding of the sequence of code starting at entry included
  # the binding is a hash showing the value of modified elements at the
  # end of the code sequence, relative to their value at entry
  # the elements are all the registers and the memory written to
  # if finish is nil, the binding will include :ip, which is the address
  # to be executed next (if it exists)
  # the binding will not include memory access from subfunctions
  # entry should be an entrypoint of the disassembler if finish is nil
  # the code sequence must have only one end, with no to_normal
  def code_binding(dasm, entry, finish=nil)
    entry = dasm.normalize(entry)
    finish = dasm.normalize(finish) if finish
    lastdi = nil
    binding = {}
    bt = lambda { |from, expr, inc_start|
      ret = dasm.backtrace(Expression[expr], from, :snapshot_addr => entry, :include_start => inc_start)
      ret.length == 1 ? ret.first : Expression::Unknown
    }

    # walk blocks, search for finish, scan memory writes
    todo = [entry]
    done = [Expression::Unknown]
    while addr = todo.pop
      addr = dasm.normalize(addr)
      next if done.include? addr or addr == finish or not dasm.decoded[addr].kind_of? DecodedInstruction
      done << addr
      b = dasm.decoded[addr].block

      next if b.list.find { |di|
        a = di.address
        if a == finish
          lastdi = b.list[b.list.index(di) - 1]
          true
        else
          # check writes from the instruction
          get_xrefs_w(dasm, di).each { |waddr, len|
            # we want the ptr expressed with reg values at entry
            ptr = bt[a, waddr, false]
            binding[Indirection[ptr, len, a]] = bt[a, Indirection[waddr, len, a], true]
          }
          false
        end
      }

      hasnext = false
      b.each_to_samefunc(dasm) { |t|
        hasnext = true
        if t == finish
          lastdi = b.list.last
        else
          todo << t
        end
      }

      # check end of sequence
      if not hasnext
        raise "two-ended code_binding #{lastdi} & #{b.list.last}" if lastdi
        lastdi = b.list.last
        if lastdi.opcode.props[:setip]
          e = get_xrefs_x(dasm, lastdi)
          raise 'bad code_binding ending' if e.to_a.length != 1 or not lastdi.opcode.props[:stopexec]
          binding[:ip] = bt[lastdi.address, e.first, false]
        elsif not lastdi.opcode.props[:stopexec]
          binding[:ip] = lastdi.next_addr
        end
      end
    end
    binding.delete_if { |k, v| Expression[k] == Expression[v] }

    # add register binding
    raise "no code_binding end" if not lastdi and not finish
    register_symbols.each { |reg|
      val =
        if lastdi; bt[lastdi.address, reg, true]
        else bt[finish, reg, false]
        end
      next if val == Expression[reg]
      mask = 0xffff_ffff	# dont use 1<<@size, because 16bit code may use e.g. edi (through opszoverride)
      mask = 0xffff_ffff_ffff_ffff if @size == 64
      val = Expression[val, :&, mask].reduce
      binding[reg] = Expression[val]
    }

    binding
  end
end
end
