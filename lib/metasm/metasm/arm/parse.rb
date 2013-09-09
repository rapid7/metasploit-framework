#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/arm/opcodes'
require 'metasm/parse'

module Metasm
class ARM
  def opcode_list_byname
    @opcode_list_byname ||= opcode_list.inject({}) { |h, o|
      (h[o.name] ||= []) << o
      if o.props[:cond]
        coff = o.props[:cond_name_off] || o.name.length
        %w[eq ne cs cc mi pl vs vc hi ls ge lt gt le al].each { |cd|
          n = o.name.dup
          n[coff, 0] = cd
          (h[n] ||= []) << o
        }
      end
      h
    }
  end

  def parse_arg_valid?(op, sym, arg)
    case sym
    when :rd, :rs, :rn, :rm; arg.kind_of? Reg and arg.shift == 0 and (arg.updated ? op.props[:baseincr] : !op.props[:baseincr])
    when :rm_rs; arg.kind_of? Reg and arg.shift.kind_of? Reg
    when :rm_is; arg.kind_of? Reg and arg.shift.kind_of? Integer
    when :i16, :i24, :i8_12, :i8_r; arg.kind_of? Expression
    when :mem_rn_rm, :mem_rn_i8_12, :mem_rn_rms, :mem_rn_i12
      os = case sym
           when :mem_rn_rm; :rm
           when :mem_rn_i8_12; :i8_12
           when :mem_rn_rms; :rm_rs
           when :mem_rn_i12; :i16
           end
      arg.kind_of? Memref and parse_arg_valid?(op, os, arg.offset)
    when :reglist; arg.kind_of? RegList
    end
    # TODO check flags on reglist, check int values
  end

  def parse_argument(lexer)
    if Reg.s_to_i[lexer.nexttok.raw]
      arg = Reg.new Reg.s_to_i[lexer.readtok.raw]
      lexer.skip_space
      case lexer.nexttok.raw.downcase
      when 'lsl', 'lsr', 'asr', 'ror'
        arg.stype = lexer.readtok.raw.downcase.to_sym
        lexer.skip_space
        if Reg.s_to_i[lexer.nexttok.raw]
          arg.shift = Reg.new Reg.s_to_i[lexer.readtok.raw]
        else
          arg.shift = Expression.parse(lexer).reduce
        end
      when 'rrx'
        lexer.readtok
        arg.stype = :ror
      when '!'
        lexer.readtok
        arg.updated = true
      end
    elsif lexer.nexttok.raw == '{'
      lexer.readtok
      arg = RegList.new
      loop do
        raise "unterminated reglist" if lexer.eos?
        lexer.skip_space
        if Reg.s_to_i[lexer.nexttok.raw]
          arg.list << Reg.new(Reg.s_to_i[lexer.readtok.raw])
          lexer.skip_space
        end
        case lexer.nexttok.raw
        when ','; lexer.readtok
        when '-'
          lexer.readtok
          lexer.skip_space
          if not r = Reg.s_to_i[lexer.nexttok.raw]
            raise lexer, "reglist parse error: invalid range"
          end
          lexer.readtok
          (arg.list.last.i+1..r).each { |v|
            arg.list << Reg.new(v)
          }
        when '}'; lexer.readtok ; break
        else raise lexer, "reglist parse error: ',' or '}' expected, got #{lexer.nexttok.raw.inspect}"
        end
      end
      if lexer.nexttok and lexer.nexttok.raw == '^'
        lexer.readtok
        arg.usermoderegs = true
      end
    elsif lexer.nexttok.raw == '['
      lexer.readtok
      if not base = Reg.s_to_i[lexer.nexttok.raw]
        raise lexer, 'invalid mem base (reg expected)'
      end
      base = Reg.new Reg.s_to_i[lexer.readtok.raw]
      if lexer.nexttok.raw == ']'
        lexer.readtok
        closed = true
      end
      if lexer.nexttok.raw != ','
        raise lexer, 'mem off expected'
      end
      lexer.readtok
      off = parse_argument(lexer)
      if not off.kind_of? Expression and not off.kind_of? Reg
        raise lexer, 'invalid mem off (reg/imm expected)'
      end
      case lexer.nexttok and lexer.nexttok.raw
      when ']'
      when ','
      end
      lexer.readtok
      arg = Memref.new(base, off)
      if lexer.nexttok and lexer.nexttok.raw == '!'
        lexer.readtok
        arg.incr = :pre	# TODO :post
      end
    else
      arg = Expression.parse lexer
    end
    arg
  end
end
end
