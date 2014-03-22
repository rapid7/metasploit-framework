#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/sh4/opcodes'
require 'metasm/decode'

module Metasm
class Sh4
  def build_opcode_bin_mask(op)
    op.bin_mask = 0
    op.args.each { |f|
      op.bin_mask |= @fields_mask[f] << @fields_shift[f]
    }
    op.bin_mask ^= 0xffff
  end

  def build_bin_lookaside
    lookaside = (0..0xf).inject({}) { |h, i| h.update i => [] }
    opcode_list.each { |op|
      build_opcode_bin_mask op
      lookaside[(op.bin >> 12) & 0xf] << op
    }
    lookaside
  end

  # depending on transfert size mode (sz flag), fmov instructions manipulate single ou double precision values
  # instruction aliasing appears when sz is not handled
  def transfer_size_mode(list)
    return list if list.find { |op| not op.name.include? 'mov' }
    @transfersz == 0 ? list.find_all { |op| op.name.include? 'fmov.s' } : list.reject { |op| op.name.include? 'fmov.s' }
  end

  # when pr flag is set, floating point instructions are executed as double-precision operations
  # thus register pair is used (DRn registers)
  def precision_mode(list)
    @fpprecision == 0 ? list.reject { |op| op.args.include? :drn } : list.find_all { |op| op.args.include? :frn }
  end

  def decode_findopcode(edata)
    di = DecodedInstruction.new(self)
    val = edata.decode_imm(:u16, @endianness)
    edata.ptr -= 2
    op = @bin_lookaside[(val >> 12) & 0xf].find_all { |opcode| (val & opcode.bin_mask) == opcode.bin }

    op = transfer_size_mode(op) if op.length == 2
    op = precision_mode(op) if op.length == 2

    if op.length > 1
      puts "current value: #{Expression[val]}, ambiguous matches:",
      op.map { |opcode| " #{opcode.name} - #{opcode.args.inspect} - #{Expression[opcode.bin]} - #{Expression[opcode.bin_mask]}" }
      #raise "Sh4 - Internal error"
    end

    if not op.empty?
      di.opcode = op.first
      di
    end
  end

  def decode_instr_op(edata, di)
    before_ptr = edata.ptr
    op = di.opcode
    di.instruction.opname = op.name
    di.opcode.props[:memsz] = (op.name =~ /\.l|mova/ ? 32 : (op.name =~ /\.w/ ? 16 : 8))
    val = edata.decode_imm(:u16, @endianness)

    field_val = lambda{ |f|
      r = (val >> @fields_shift[f]) & @fields_mask[f]
      case f
      when :@rm, :@rn ,:@_rm, :@_rn, :@rm_, :@rn_; GPR.new(r)
      when :@disppc
        # The effective address is formed by calculating PC+4,
        # clearing the lowest 2 bits, and adding the zero-extended 8-bit immediate i
        # multiplied by 4 (32-bit)/ 2 (16-bit) / 1 (8-bit).
        curaddr = di.address+4
        curaddr = (curaddr & 0xffff_fffc) if di.opcode.props[:memsz] == 32
        curaddr+r*(di.opcode.props[:memsz]/8)
      when :@disprm, :@dispr0rn; (r & 0xf) * (di.opcode.props[:memsz]/8)
      when :@disprmrn; (r & 0xf) * 4
      when :@dispgbr; Expression.make_signed(r, 16)
      when :disp8; di.address+4+2*Expression.make_signed(r, 8)
      when :disp12; di.address+4+2*Expression.make_signed(r, 12)
      when :s8; Expression.make_signed(r, 8)
      else r
      end
    }

    op.args.each { |a|
      di.instruction.args << case a
      when :r0; GPR.new 0
      when :rm, :rn; GPR.new field_val[a]
      when :rm_bank, :rn_bank; RBANK.new field_val[a]
      when :drm, :drn; DR.new field_val[a]
      when :frm, :frn; FR.new field_val[a]
      when :xdm, :xdn; XDR.new field_val[a]
      when :fvm, :fvn; FVR.new field_val[a]
      when :vbr; VBR.new
      when :gbr; GBR.new
      when :sr; SR.new
      when :ssr; SSR.new
      when :spc; SPC.new
      when :sgr; SGR.new
      when :dbr; DBR.new
      when :mach; MACH.new
      when :macl; MACL.new
      when :pr; PR.new
      when :fpul; FPUL.new
      when :fpscr; FPSCR.new
      when :pc; PC.new

      when :@rm, :@rn, :@disppc
        Memref.new(field_val[a], nil)
      when :@_rm, :@_rn
        Memref.new(field_val[a], nil, :pre)
      when :@rm_, :@rn_
        Memref.new(field_val[a], nil, :post)
      when :@r0rm
        Memref.new(GPR.new(0), GPR.new(field_val[:rm]))
      when :@r0rn, :@dispr0rn
        Memref.new(GPR.new(0), GPR.new(field_val[:rn]))
      when :@disprm
        Memref.new(field_val[a], GPR.new(field_val[:rm]))
      when :@disprmrn
        Memref.new(field_val[a], GPR.new(field_val[:rn]))

      when :disppc; Expression[field_val[:@disppc]]
      when :s8, :disp8, :disp12; Expression[field_val[a]]
      when :i16, :i8, :i5; Expression[field_val[a]]

      else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
      end
    }

    di.bin_length += edata.ptr - before_ptr

    return if edata.ptr > edata.length

    di
  end

  def disassembler_default_func
    df = DecodedFunction.new
    df.backtrace_binding = {}
    (0..7 ).each { |i| r = "r#{i}".to_sym ; df.backtrace_binding[r] = Expression::Unknown }
    (8..15).each { |i| r = "r#{i}".to_sym ; df.backtrace_binding[r] = Expression[r] }
    df.backtracked_for = [BacktraceTrace.new(Expression[:pr], :default, Expression[:pr], :x)]
    df.btfor_callback = lambda { |dasm, btfor, funcaddr, calladdr|
      if funcaddr != :default
        btfor
      elsif di = dasm.decoded[calladdr] and di.opcode.props[:saveip]
        btfor
      else
        []
      end
    }
    df
  end

  def backtrace_update_function_binding(dasm, faddr, f, retaddrlist, *wantregs)
    retaddrlist.map! { |retaddr| dasm.decoded[retaddr] ? dasm.decoded[retaddr].block.list.last.address : retaddr } if retaddrlist
    b = f.backtrace_binding

    bt_val = lambda { |r|
      next if not retaddrlist
      bt = []
      b[r] = Expression::Unknown	# break recursive dep
      retaddrlist.each { |retaddr|
        bt |= dasm.backtrace(Expression[r], retaddr,
          :include_start => true, :snapshot_addr => faddr, :origin => retaddr)
      }
      b[r] = ((bt.length == 1) ? bt.first : Expression::Unknown)
    }
    wantregs = GPR::Sym if wantregs.empty?
    wantregs.map { |r| r.to_sym }.each(&bt_val)
  end


  # interprets a condition code (in an opcode name) as an expression
  def decode_cmp_expr(di, a0, a1)
    case di.opcode.name
    when 'cmp/eq'; Expression[a0, :'==', a1]
    when 'cmp/ge'; Expression[a0, :'>=', a1] # signed
    when 'cmp/gt'; Expression[a0, :'>', a1] # signed
    when 'cmp/hi'; Expression[a0, :'>', a1] # unsigned
    when 'cmp/hs'; Expression[a0, :'>=', a1] # unsigned
    end
  end

  def decode_cmp_cst(di, a0)
    case di.opcode.name
    when 'cmp/pl'; Expression[a0, :'>', 0] # signed
    when 'cmp/pz'; Expression[a0, :'>=', 0] # signed
    end
  end

  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end

  def opsz(di)
    ret = @size
    ret = 8 if di and di.opcode.name =~ /\.b/
    ret = 16 if di and di.opcode.name =~ /\.w/
    ret
  end

  def init_backtrace_binding
    @backtrace_binding ||= {}

    mask = lambda { |di| (1 << opsz(di)) - 1 }  # 32bits => 0xffff_ffff

    opcode_list.map { |ol| ol.name }.uniq.each { |op|
      @backtrace_binding[op] ||= case op
      when 'ldc', 'ldc.l', 'lds', 'lds.l', 'stc', 'stc.l', 'mov', 'mov.l', 'sts', 'sts.l'
        lambda { |di, a0, a1| { a1 => Expression[a0] }}
      when 'stc.w', 'stc.b', 'mov.w', 'mov.b'
        lambda { |di, a0, a1| { a1 => Expression[a0, :&, mask[di]] }}
      when 'movt'; lambda { |di, a0| { a0 => :t_bit }}
      when 'mova'; lambda { |di, a0, a1| { a1 => Expression[a0] }}
      when 'exts.b', 'exts.w', 'extu.w'
        lambda { |di, a0, a1| { a1 => Expression[a0, :&, mask[di]] }}
      when 'cmp/eq', 'cmp/ge', 'cmp/ge', 'cmp/gt', 'cmp/hi', 'cmp/hs'
        lambda { |di, a0, a1| { :t_bit => decode_cmp_expr(di, a0, a1) }}
      when 'cmp/pl', 'cmp/pz'
        lambda { |di, a0| { :t_bit => decode_cmp_cst(di, a0) }}
      when 'tst'; lambda { |di, a0, a1| { :t_bit => Expression[[a0, :&, mask[di]], :==, [a1, :&, mask[di]]] }}
      when 'rte'; lambda { |di| { :pc => :spc , :sr => :ssr }}
      when 'rts'; lambda { |di| { :pc => :pr }}
      when 'sets'; lambda { |di| { :s_bit => 1 }}
      when 'sett'; lambda { |di| { :t_bit => 1 }}
      when 'clrs'; lambda { |di| { :s_bit => 0 }}
      when 'clrt'; lambda { |di| { :t_bit => 0 }}
      when 'clrmac'; lambda { |di| { :macl => 0, :mach => 0 }}
      when 'jmp'; lambda { |di, a0| { :pc => a0 }}
      when 'jsr', 'bsr', 'bsrf'; lambda { |di, a0| { :pc => Expression[a0], :pr => Expression[di.address, :+, 2*2] }}
      when 'dt'; lambda { |di, a0|
        res = Expression[a0, :-, 1]
        { :a0 => res, :t_bit => Expression[res, :==, 0] }
      }
      when 'add' ; lambda { |di, a0, a1| { a1 => Expression[[a0, :+, a1], :&, 0xffff_ffff] }}
      when 'addc' ; lambda { |di, a0, a1|
        res = Expression[[a0, :&, mask[di]], :+, [[a1, :&, mask[di]], :+, :t_bit]]
        { a1 => Expression[a0, :+, [a1, :+, :t_bit]], :t_bit => Expression[res, :>, mask[di]] }
      }
      when 'addv' ; lambda { |di, a0, a1|
        res = Expression[[a0, :&, mask[di]], :+, [[a1, :&, mask[di]]]]
        { a1 => Expression[a0, :+, [a1, :+, :t_bit]], :t_bit => Expression[res, :>, mask[di]] }
      }
      when 'shll16', 'shll8', 'shll2', 'shll' ; lambda { |di, a0|
        shift = { 'shll16' => 16, 'shll8' => 8, 'shll2' => 2, 'shll' => 1 }[op]
        { a0 => Expression[[a0, :<<, shift], :&, 0xffff] }
      }
      when 'shlr16', 'shlr8', 'shlr2','shlr'; lambda { |di, a0|
        shift = { 'shlr16' => 16, 'shlr8' => 8, 'shlr2' => 2, 'shlr' => 1 }[op]
        { a0 => Expression[a0, :>>, shift] }
      }
      when 'rotcl'; lambda { |di, a0| { a0 => Expression[[a0, :<<, 1], :|, :t_bit], :t_bit => Expression[a0, :>>, [opsz[di], :-, 1]] }}
      when 'rotcr'; lambda { |di, a0| { a0 => Expression[[a0, :>>, 1], :|, :t_bit], :t_bit => Expression[a0, :&, 1] }}
      when 'rotl'; lambda { |di, a0|
        shift_bit = [a0, :<<, [opsz[di], :-, 1]]
        { a0 => Expression[[a0, :<<, 1], :|, shift_bit], :t_bit => shift_bit }
      }
      when 'rotr'; lambda { |di, a0|
        shift_bit = [a0, :>>, [opsz[di], :-, 1]]
        { a0 => Expression[[a0, :>>, 1], :|, shift_bit], :t_bit => shift_bit }
      }
      when 'shal'; lambda { |di, a0|
        shift_bit = [a0, :<<, [opsz[di], :-, 1]]
        { a0 => Expression[a0, :<<, 1], :t_bit => shift_bit }
      }
      when 'shar'; lambda { |di, a0|
        shift_bit = Expression[a0, :&, 1]
        { a0 => Expression[a0, :>>, 1], :t_bit => shift_bit }
      }
      when 'sub';  lambda { |di, a0, a1| { a1 => Expression[[a1, :-, a0], :&, 0xffff_ffff] }}
      when 'subc'; lambda { |di, a0, a1| { a1 => Expression[a1, :-, [a0, :-, :t_bit]] }}
      when 'and', 'and.b'; lambda { |di, a0, a1| { a1 => Expression[[a0, :&, mask[di]], :|, [[a1, :&, mask[di]]]] }}
      when 'or', 'or.b';   lambda { |di, a0, a1| { a1 => Expression[[a0, :|, mask[di]], :|, [[a1, :&, mask[di]]]] }}
      when 'xor', 'xor.b'; lambda { |di, a0, a1| { a1 => Expression[[a0, :|, mask[di]], :^, [[a1, :&, mask[di]]]] }}
      when 'neg' ;  lambda { |di, a0, a1| { a1 => Expression[mask[di], :-, a0] }}
      when 'negc' ; lambda { |di, a0, a1| { a1 => Expression[[[mask[di], :-, a0], :-, :t_bit], :&, mask[di]] }}
      when 'not';   lambda { |di, a0, a1| { a1 => Expression[a0, :^, mask[di]] }}
      when 'nop'; lambda { |*a| {} }
      when /^b/; lambda { |*a| {} }	# branches
      end
    }

    @backtrace_binding
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when GPR, XFR, XDR, FVR, DR, FR, XMTRX; arg.symbolic
      when MACH, MACL, PR, FPUL, PC, FPSCR; arg.symbolic
      when SR, SSR, SPC, GBR, VBR, SGR, DBR; arg.symbolic
      when Memref; arg.symbolic(di.address, di.opcode.props[:memsz]/8)
      else arg
      end
    }

    if binding = backtrace_binding[di.opcode.basename]
      bd = binding[di, *a] || {}
      di.instruction.args.grep(Memref).each { |m|
        next unless r = m.base and r.kind_of?(GPR)
        r = r.symbolic
        case m.action
        when :post
          bd[r] ||= Expression[r, :+, di.opcode.props[:memsz]/8]
        when :pre
          bd[r] ||= Expression[r, :-, di.opcode.props[:memsz]/8]
        end
      }
      bd
    else
      puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
      {:incomplete_binding => Expression[1]}
    end
  end

  def get_xrefs_x(dasm, di)
    return [] if not di.opcode.props[:setip]

    val = case di.instruction.opname
          when 'rts'; :pr
          else di.instruction.args.last
          end

    val = case val
          when Reg; val.symbolic
          when Memref; arg.symbolic(di.address, 4)
          else val
          end

    val = case di.instruction.opname
          when 'braf', 'bsrf'; Expression[[di.address, :+, 4], :+, val]
          else val
          end

    [Expression[val]]
  end

  def backtrace_is_function_return(expr, di=nil)
    expr.reduce_rec == :pr
  end

  def delay_slot(di=nil)
    (di and di.opcode.props[:delay_slot]) ? 1 : 0
  end

  def replace_instr_arg_immediate(i, old, new)
    i.args.map! { |a|
      case a
      when Expression; a == old ? new : Expression[a.bind(old => new).reduce]
      when Memref
        a.base = (a.base == old ? new : Expression[a.base.bind(old => new).reduce]) if a.base.kind_of?(Expression)
        a
      else a
      end
    }
  end
end
end
