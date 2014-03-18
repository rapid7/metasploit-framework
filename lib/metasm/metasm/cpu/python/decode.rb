#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/python/opcodes'
require 'metasm/decode'

module Metasm
class Python
  def build_bin_lookaside
    opcode_list.inject({}) { |la, op| la.update op.bin => op }
  end

  def decode_findopcode(edata)
    di = DecodedInstruction.new(self)

    byte = edata.decode_imm(:u8, :little)

    di if di.opcode = @bin_lookaside[byte]
  end

  def decode_instr_op(edata, di)
    di.bin_length = 1

    di.instruction.opname = di.opcode.name

    di.opcode.args.each { |a|
      case a
      when :cmp
        di.bin_length += 2
        v = edata.decode_imm(:i16, @endianness)
        di.instruction.args << (CMP_OP[v] || Expression[v])
      when :i16
        di.bin_length += 2
        di.instruction.args << Expression[edata.decode_imm(:i16, @endianness)]
      when :u8
        di.bin_length += 1
        di.instruction.args << Expression[edata.decode_imm(:u8, @endianness)]
      else
        raise "unsupported arg #{a.inspect}"
      end
    }

    return if edata.ptr > edata.length

    di
  end

  def decode_instr_interpret(di, addr)
    case di.opcode.name
    when 'LOAD_CONST'
      if c = prog_code(addr)
        cst = c[:consts][di.instruction.args.first.reduce]
        if cst.kind_of? Hash and cst[:type] == :code
          di.add_comment "lambda #{Expression[cst[:fileoff]]}"
        else
          di.add_comment cst.inspect
        end
      end
    when 'LOAD_NAME', 'LOAD_ATTR', 'LOAD_GLOBAL', 'STORE_NAME', 'IMPORT_NAME', 'LOAD_FAST'
      if c = prog_code(addr)
        di.add_comment c[:names][di.instruction.args.first.reduce].inspect
      end
    end
    di
  end

  def backtrace_binding
    @backtrace_binding ||= init_backtrace_binding
  end

  def init_backtrace_binding
    @backtrace_binding ||= {}

    opcode_list.each { |op|
      binding = case op
          when 'nop'; lambda { |*a| {} }
          end
      @backtrace_binding[op] ||= binding if binding
    }

    @backtrace_binding
  end

  def get_backtrace_binding(di)
    a = di.instruction.args.map { |arg|
      case arg
      when Var; arg.symbolic
      else arg
      end
    }

    if binding = backtrace_binding[di.opcode.basename]
      binding[di, *a]
    else
      puts "unhandled instruction to backtrace: #{di}" if $VERBOSE
      { :incomplete_binding => Expression[1] }
    end
  end

  def get_xrefs_x(dasm, di)
    return [] if not di.opcode.props[:setip]

    arg =	case di.opcode.name
      when 'JUMP_FORWARD', 'FOR_ITER'
        # relative offset
        di.instruction.args.last.reduce + di.next_addr
      when 'CALL_FUNCTION_VAR'
        'lol'
      when /CALL/
          :unknown
      else
        # absolute offset from :code start
        off = di.instruction.args.last.reduce
        if c = prog_code(di)
          off += c[:fileoff]
        end
        off
      end

    [Expression[(arg.kind_of?(Var) ? arg.symbolic : arg)]]
  end

  def prog_code(addr)
    addr = addr.address if addr.kind_of? DecodedInstruction
    @last_prog_code ||= nil
    return @last_prog_code if @last_prog_code and @last_prog_code[:fileoff] <= addr and @last_prog_code[:fileoff] + @last_prog_code[:code].length > addr
    @last_prog_code = @program.code_at_off(addr) if @program
  end

  def backtrace_is_function_return(expr, di=nil)
    #Expression[expr].reduce == Expression['wtf']
  end
end
end
