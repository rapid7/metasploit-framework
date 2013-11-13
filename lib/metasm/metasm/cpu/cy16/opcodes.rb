#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/cy16/main'

module Metasm

class CY16
  def addop(name, bin, *args)
    o = Opcode.new name, bin
    args.each { |a|
      o.args << a if @fields_mask[a] or @valid_args[a]
      o.props[a] = true if @valid_props[a]
      o.fields[a] = @fields_shift[a] if @fields_mask[a]
      raise "wtf #{a.inspect}" unless @valid_args[a] or @valid_props[a] or @fields_mask[a]
    }
    @opcode_list << o
  end

  def addop_macrocc(name, bin, *args)
    %w[z nz b ae s ns o no a be g ge l le].each_with_index { |cc, i|
      dbin = bin
      dbin |= i << 8
      addop name + cc, dbin, *args
    }
  end

  def init_cy16
    @opcode_list = []
    @valid_args.update [:rs, :rd, :o7
    ].inject({}) { |h, v| h.update v => true }
    @fields_mask.update :rs => 0x3f, :rd => 0x3f, :o7 => 0x7f, :x7 => 0x7f, :u3 => 7
    @fields_shift.update :rs => 6, :rd => 0, :o7 => 0, :x7 => 0, :u3 => 6

    addop 'mov', 0<<12, :rs, :rd
    addop 'add', 1<<12, :rs, :rd
    addop 'adc', 2<<12, :rs, :rd
    addop 'addc',2<<12, :rs, :rd
    addop 'sub', 3<<12, :rs, :rd
    addop 'sbb', 4<<12, :rs, :rd
    addop 'subb',4<<12, :rs, :rd
    addop 'cmp', 5<<12, :rs, :rd
    addop 'and', 6<<12, :rs, :rd
    addop 'test',7<<12, :rs, :rd
    addop 'or',  8<<12, :rs, :rd
    addop 'xor', 9<<12, :rs, :rd

    addop_macrocc 'int', (10<<12), :x7
    addop 'int', (10<<12) | (15<<8), :x7
    addop_macrocc 'c', (10<<12) | (1<<7), :setip, :saveip, :rd
    addop 'call',(10<<12) | (15<<8) | (1<<7), :setip, :stopexec, :saveip, :rd
    addop_macrocc 'r', (12<<12) | (1<<7) | 0b010111, :setip	# must come before absolute jmp
    addop 'ret', (12<<12) | (15<<8) | (1<<7) | 0b010111, :setip, :stopexec
    addop_macrocc 'j', (12<<12), :setip, :o7	# relative
    addop 'jmp', (12<<12) | (15<<8), :setip, :stopexec, :o7	# relative
    addop_macrocc 'j', (12<<12) | (1<<7), :setip, :rd	# absolute
    addop 'jmp', (12<<12) | (15<<8) | (1<<7), :setip, :stopexec, :rd	# absolute

    addop 'shr', (13<<12) | (0<<9), :u3, :rd
    addop 'shl', (13<<12) | (1<<9), :u3, :rd
    addop 'ror', (13<<12) | (2<<9), :u3, :rd
    addop 'rol', (13<<12) | (3<<9), :u3, :rd
    addop 'addi',(13<<12) | (4<<9), :u3, :rd
    addop 'subi',(13<<12) | (5<<9), :u3, :rd
    addop 'not', (13<<12) | (7<<9) | (0<<6), :rd
    addop 'neg', (13<<12) | (7<<9) | (1<<6), :rd
    addop 'cbw', (13<<12) | (7<<9) | (4<<6), :rd
    addop 'sti', (13<<12) | (7<<9) | (7<<6) | 0
    addop 'cli', (13<<12) | (7<<9) | (7<<6) | 1
    addop 'stc', (13<<12) | (7<<9) | (7<<6) | 2
    addop 'clc', (13<<12) | (7<<9) | (7<<6) | 3
  end

  alias init_latest init_cy16
end
end
