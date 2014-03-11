#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/z80/opcodes'
require 'metasm/decode'

module Metasm
class Z80
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
      next @unknown_opcode = op if not b
      for i in b..(b | (255^msk))
        lookaside[i] << op if i & msk == b & msk
      end
    }
    lookaside
  end

  def decode_prefix(instr, byte)
    case byte
    when 0xDD; instr.prefix = 0xDD
    when 0xFD; instr.prefix = 0xFD
    # implicit 'else return false'
    end
  end

  # tries to find the opcode encoded at edata.ptr
  # if no match, tries to match a prefix (update di.instruction.prefix)
  # on match, edata.ptr points to the first byte of the opcode (after prefixes)
  def decode_findopcode(edata)
    di = DecodedInstruction.new self
    while edata.ptr < edata.data.length
      byte = edata.data[edata.ptr]
      byte = byte.unpack('C').first if byte.kind_of?(::String)
      return di if di.opcode = @bin_lookaside[byte].find { |op|
        # fetch the relevant bytes from edata
        bseq = edata.data[edata.ptr, op.bin.length].unpack('C*')
        # check against full opcode mask
        op.bin.zip(bseq, op.bin_mask).all? { |b1, b2, m| b2 and ((b1 & m) == (b2 & m)) }
      }

      if decode_prefix(di.instruction, edata.get_byte)
        nb = edata.data[edata.ptr]
        nb = nb.unpack('C').first if nb.kind_of?(::String)
        case nb
        when 0xCB
          # DD CB <disp8> <opcode_pfxCB> [<args>]
          di.instruction.prefix |= edata.get_byte	<< 8
          di.bin_length += 2
          opc = edata.data[edata.ptr+1]
          opc = opc.unpack('C').first if opc.kind_of?(::String)
          bseq = [0xCB, opc]
          # XXX in decode_instr_op, byte[0] is the immediate displacement instead of cb
          return di if di.opcode = @bin_lookaside[nb].find { |op|
            op.bin.zip(bseq, op.bin_mask).all? { |b1, b2, m| b2 and ((b1 & m) == (b2 & m)) }
          }
        when 0xED
          di.instruction.prefix = nil
        end
      else
        di.opcode = @unknown_opcode
        return di
      end
      di.bin_length += 1
    end
  end


  def decode_instr_op(edata, di)
    before_ptr = edata.ptr
    op = di.opcode
    di.instruction.opname = op.name
    bseq = edata.read(op.bin.length).unpack('C*')		# decode_findopcode ensures that data >= op.length
    pfx = di.instruction.prefix

    field_val = lambda { |f|
      if fld = op.fields[f]
        (bseq[fld[0]] >> fld[1]) & @fields_mask[f]
      end
    }

    op.args.each { |a|
      di.instruction.args << case a
      when :i8, :u8, :i16, :u16; Expression[edata.decode_imm(a, @endianness)]
      when :iy; Expression[field_val[a]]
      when :iy8; Expression[field_val[a]*8]

      when :rp
        v = field_val[a]
        Reg.new(16, v)
      when :rp2
        v = field_val[a]
        v = 4 if v == 3
        Reg.new(16, v)
      when :ry, :rz
        v = field_val[a]
        if v == 6
          Memref.new(Reg.from_str('HL'), nil, 1)
        else
          Reg.new(8, v)
        end

      when :r_a;   Reg.from_str('A')
      when :r_af;  Reg.from_str('AF')
      when :r_hl;  Reg.from_str('HL')
      when :r_de;  Reg.from_str('DE')
      when :r_sp;  Reg.from_str('SP')
      when :r_i;   Reg.from_str('I')

      when :m16;  Memref.new(nil, edata.decode_imm(:u16, @endianness), nil)
      when :m_bc; Memref.new(Reg.from_str('BC'), nil, 1)
      when :m_de; Memref.new(Reg.from_str('DE'), nil, 1)
      when :m_sp; Memref.new(Reg.from_str('SP'), nil, 2)
      when :m_hl; Memref.new(Reg.from_str('HL'), nil, 1)
      when :mf8;  Memref.new(nil, 0xff00 + edata.decode_imm(:u8, @endianness), 1)
      when :mfc;  Memref.new(Reg.from_str('C'), 0xff00, 1)

      else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
      end
    }

    case pfx
    when 0xDD
    when 0xFD
    when 0xCBDD
    when 0xCBFD
    end

    di.bin_length += edata.ptr - before_ptr

    return if edata.ptr > edata.length

    di
  end

  # hash opcode_name => lambda { |dasm, di, *symbolic_args| instr_binding }
  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end
  def backtrace_binding=(b) @backtrace_binding = b end

  # populate the @backtrace_binding hash with default values
  def init_backtrace_binding
    @backtrace_binding ||= {}

    mask = 0xffff

    opcode_list.map { |ol| ol.basename }.uniq.sort.each { |op|
      binding = case op
      when 'ld'; lambda { |di, a0, a1, *aa| a2 = aa[0] ; a2 ? { a0 => Expression[a1, :+, a2] } : { a0 => Expression[a1] } }
      when 'ldi'; lambda { |di, a0, a1| hl = (a0 == :a ? a1 : a0) ; { a0 => Expression[a1], hl => Expression[hl, :+, 1] } }
      when 'ldd'; lambda { |di, a0, a1| hl = (a0 == :a ? a1 : a0) ; { a0 => Expression[a1], hl => Expression[hl, :-, 1] } }
      when 'add', 'adc', 'sub', 'sbc', 'and', 'xor', 'or'
        lambda { |di, a0, a1|
          e_op = { 'add' => :+, 'adc' => :+, 'sub' => :-, 'sbc' => :-, 'and' => :&, 'xor' => :^, 'or' => :| }[op]
          ret = Expression[a0, e_op, a1]
          ret = Expression[ret, e_op, :flag_c] if op == 'adc' or op == 'sbc'
          ret = Expression[ret.reduce] if not a0.kind_of? Indirection
          { a0 => ret }
        }
      when 'cp', 'cmp'; lambda { |di, *a| {} }
      when 'inc'; lambda { |di, a0| { a0 => Expression[a0, :+, 1] } }
      when 'dec'; lambda { |di, a0| { a0 => Expression[a0, :-, 1] } }
      when 'not'; lambda { |di, a0| { a0 => Expression[a0, :^, mask] } }
      when 'push'
        lambda { |di, a0| { :sp => Expression[:sp, :-, 2],
          Indirection[:sp, 2, di.address] => Expression[a0] } }
      when 'pop'
        lambda { |di, a0| { :sp => Expression[:sp, :+, 2],
          a0 => Indirection[:sp, 2, di.address] } }
      when 'call'
        lambda { |di, a0| { :sp => Expression[:sp, :-, 2],
            Indirection[:sp, 2, di.address] => Expression[di.next_addr] }
        }
      when 'ret', 'reti'; lambda { |di, *a| { :sp => Expression[:sp, :+, 2] } }
      # TODO callCC, retCC ...
      when 'bswap'
        lambda { |di, a0| { a0 => Expression[
            [[a0, :&, 0xff00], :>>,  8], :|,
            [[a0, :&, 0x00ff], :<<,  8]] } }
      when 'nop', /^j/; lambda { |di, *a| {} }
      end

      # TODO flags ?

      @backtrace_binding[op] ||= binding if binding
    }
    @backtrace_binding
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when Memref, Reg; arg.symbolic(di)
      else arg
      end
    }

    if binding = backtrace_binding[di.opcode.basename]
      binding[di, *a]
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

  # patch a forward binding from the backtrace binding
  def fix_fwdemu_binding(di, fbd)
    case di.opcode.name
    when 'push', 'call'; fbd[Indirection[[:sp, :-, 2], 2]] = fbd.delete(Indirection[:sp, 2])
    end
    fbd
  end

  def get_xrefs_x(dasm, di)
    return [] if not di.opcode.props[:setip]

    case di.opcode.basename
    when 'ret', 'reti'
      return [Indirection[:sp, 2, di.address]]
    when /^jr|^djnz/
      # jmp/call are absolute addrs, only jr/djnz are relative
      # also, the asm source should display the relative offset
      return [Expression[[di.address, :+, di.bin_length], :+, di.instruction.args.first]]
    end

    case tg = di.instruction.args.first
    when Memref; [Expression[tg.symbolic(di)]]
    when Reg; [Expression[tg.symbolic(di)]]
    when Expression, ::Integer; [Expression[tg]]
    else
      puts "unhandled setip at #{di.address} #{di.instruction}" if $DEBUG
      []
    end
  end

  # checks if expr is a valid return expression matching the :saveip instruction
  def backtrace_is_function_return(expr, di=nil)
    expr = Expression[expr].reduce_rec
    expr.kind_of?(Indirection) and expr.len == 2 and expr.target == Expression[:sp]
  end

  # updates the function backtrace_binding
  # if the function is big and no specific register is given, do nothing (the binding will be lazily updated later, on demand)
  def backtrace_update_function_binding(dasm, faddr, f, retaddrlist, *wantregs)
    b = f.backtrace_binding

    bt_val = lambda { |r|
      next if not retaddrlist
      b[r] = Expression::Unknown
      bt = []
      retaddrlist.each { |retaddr|
        bt |= dasm.backtrace(Expression[r], retaddr, :include_start => true,
               :snapshot_addr => faddr, :origin => retaddr)
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
      bt_val[:sp]
    end

    b
  end

  # returns true if the expression is an address on the stack
  def backtrace_is_stack_address(expr)
    Expression[expr].expr_externals.include?(:sp)
  end

  # updates an instruction's argument replacing an expression with another (eg label renamed)
  def replace_instr_arg_immediate(i, old, new)
    i.args.map! { |a|
      case a
      when Expression; a == old ? new : Expression[a.bind(old => new).reduce]
      when Memref
        a.offset = (a.offset == old ? new : Expression[a.offset.bind(old => new).reduce]) if a.offset
        a
      else a
      end
    }
  end
end
end
