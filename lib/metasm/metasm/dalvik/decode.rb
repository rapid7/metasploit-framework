#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/dalvik/opcodes'
require 'metasm/decode'

module Metasm
class Dalvik
  def build_bin_lookaside
  end

  def decode_findopcode(edata)
    return if edata.ptr >= edata.data.length
    di = DecodedInstruction.new(self)
    di.opcode = opcode_list[edata.decode_imm(:u16, @endianness) & 0xff]
    edata.ptr -= 2
    di
  end

  def decode_instr_op(edata, di)
    op = di.opcode
    di.instruction.opname = op.name
    
    val = [edata.decode_imm(:u16, @endianness)]

    op.args.each { |a|
      di.instruction.args << case a
      when :i16
        val << edata.decode_imm(:i16, @endianness)
        Expression[val.last]
      when :u16
        val << edata.decode_imm(:u16, @endianness)
        Expression[val.last]
      when :r16
        val << edata.decode_imm(:u16, @endianness)
        Reg.new(val.last)
      when :i16_32hi
        val << edata.decode_imm(:i16, @endianness)
        Expression[val.last << 16]
      when :i16_64hi
        val << edata.decode_imm(:i16, @endianness)
        Expression[val.last << 48]
      when :i32
        val << edata.decode_imm(:u16, @endianness)
        val << edata.decode_imm(:i16, @endianness)
        Expression[val[-2] | (val[-1] << 16)]
      when :u32
        val << edata.decode_imm(:u16, @endianness)
        val << edata.decode_imm(:u16, @endianness)
        Expression[val[-2] | (val[-1] << 16)]
      when :u64
        val << edata.decode_imm(:u16, @endianness)
        val << edata.decode_imm(:u16, @endianness)
        val << edata.decode_imm(:u16, @endianness)
        val << edata.decode_imm(:u16, @endianness)
        Expression[val[-4] | (val[-3] << 16) | (val[-2] << 32) | (val[-1] << 48)]
      when :ra
        Reg.new((val[0] >> 8) & 0xf)
      when :rb
        Reg.new((val[0] >> 12) & 0xf)
      when :ib
        Expression[Expression.make_signed((val[0] >> 12) & 0xf, 4)]
      when :raa
        Reg.new((val[0] >> 8) & 0xff)
      when :iaa
        Expression[Expression.make_signed((val[0] >> 8) & 0xff, 8)]
      when :rbb
        val[1] ||= edata.decode_imm(:u16, @endianness)
        Reg.new(val[1] & 0xff)
      when :ibb
        val[1] ||= edata.decode_imm(:u16, @endianness)
        Expression[Expression.make_signed(val[1] & 0xff, 8)]
      when :rcc
        val[1] ||= edata.decode_imm(:u16, @endianness)
        Reg.new((val[1] >> 8) & 0xff)
      when :icc
        val[1] ||= edata.decode_imm(:u16, @endianness)
        Expression[Expression.make_signed((val[1] >> 8) & 0xff, 8)]
      when :rlist4, :rlist5
        cnt = (val[0] >> 12) & 0xf
               val << edata.decode_imm(:u16, @endianness)
        [cnt, 4].min.times {
          di.instruction.args << Reg.new(val[-1] & 0xf)
          val[-1] >>= 4
        }
        di.instruction.args << Reg.new((val[0] >> 8) & 0xf) if cnt > 4
        next
      when :rlist16
        cnt = (val[0] >> 8) & 0xff
        val << edata.decode_imm(:u16, @endianness)
        cnt.times { |c|
          di.instruction.args << Reg.new(val[-1] + c)
        }
        next
      when :m16
        val << edata.decode_imm(:u16, @endianness)
        Method.new(@dex, val.last)
      else raise SyntaxError, "Internal error: invalid argument #{a} in #{op.name}"
      end
    }

    di.bin_length = val.length*2

    di
  end

  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end
 
  def init_backtrace_binding
    @backtrace_binding ||= {}
    sz = @size/8
    @opcode_list.each { |op|
      case op.name
      when /invoke/
        @backtrace_binding[op.name] = lambda { |di, *args| {
          :callstack => Expression[:callstack, :-, sz], 
          Indirection[:callstack, sz] => Expression[di.next_addr]
        } }
      when /return/
        @backtrace_binding[op.name] = lambda { |di, *args| {
                 :callstack => Expression[:callstack, :+, sz]
        } }
      end
    }
    @backtrace_binding
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when Reg; arg.symbolic
      else arg
      end
    }
  
    if binding = backtrace_binding[di.opcode.name]
      bd = binding[di, *a]
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
    if di.opcode.props[:saveip]
      m = di.instruction.args.first
      if m.kind_of? Method and m.off
        [m.off]
      else
        [:default]
      end
    elsif di.opcode.props[:setip]
      if di.opcode.name =~ /return/
        [Indirection[:callstack, @size/8]]
      else
      []	#	[di.instruction.args.last]
      end
    else
      []
    end
  end

  # returns a DecodedFunction suitable for :default
  # uses disassembler_default_bt{for/bind}_callback
  def disassembler_default_func
    df = DecodedFunction.new
    ra = Indirection[:callstack, @size/8]
    df.backtracked_for << BacktraceTrace.new(ra, :default, ra, :x, nil)
    df.backtrace_binding[:callstack] = Expression[:callstack, :+, @size/8]
    df.btfor_callback = lambda { |dasm, btfor, funcaddr, calladdr|
      if funcaddr != :default
        btfor
      elsif di = dasm.decoded[calladdr] and di.opcode.props[:saveip]
        btfor
      else []
      end
    }

    df
  end

  def backtrace_is_function_return(expr, di=nil)
    expr and Expression[expr] == Expression[Indirection[:callstack, @size/8]]
  end
end
end
