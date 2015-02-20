#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2010 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/msp430/main'

module Metasm
class MSP430
  def addop(name, bin, *args)
    o = Opcode.new name, bin

    args.each { |a|
      o.args << a if @valid_args[a]
      o.props[a] = true if @valid_props[a]
      o.fields[a] = [@fields_mask[a], @fields_shift[a]] if @fields_mask[a]
    }

    @opcode_list << o
  end

  def init
    @opcode_list = []

    @fields_mask = {
      :as => 3,	# adressing mode
      :ad => 1,	# adressing mode
      :rd => 0xf,
      :rs => 0xf,
      :joff => 0x3ff,	# signed offset for jumps
    }
    @fields_shift = {
      :as => 4,
      :ad => 7,
      :rd => 0,
      :rs => 8,
      :joff => 0,
    }
    @valid_args = { :r_pc => true, :rd => true, :rs => true, :joff => true }
    @valid_props = { :setip => true, :stopexec => true, :saveip => true, :byte => true }

    # https://en.wikipedia.org/wiki/TI_MSP430

    addop_macro1 'rrc',  0, :byte
    addop_macro1 'swpb', 1
    addop_macro1 'rra',  2, :byte
    addop_macro1 'sxt',  3
    addop_macro1 'push', 4, :byte
    addop_macro1 'call', 5, :setip, :stopexec, :saveip

    addop 'reti', 0b000100_110_0000000

    addop_macro2 'jnz', 0
    addop_macro2 'jz',  1
    addop_macro2 'jnc', 2
    addop_macro2 'jc',  3
    addop_macro2 'jb',  4	# 'jn' jump if negative => jl unsigned ?
    addop_macro2 'jge', 5
    addop_macro2 'jl',  6
    addop_macro2 'jmp', 7, :stopexec

    addop 'ret', 0x4130, :setip, :stopexec	# mov pc, [sp++]
    addop 'pop', 0x4130, :rd, :ad		# mov rd, [sp++]

    addop_macro3 'mov', 4
    addop_macro3 'add', 5
    addop_macro3 'adc', 6	# 'addc'
    addop_macro3 'sbc', 7
    addop_macro3 'sub', 8
    addop_macro3 'cmp', 9
    addop_macro3 'dadd',10	# decimal add with carry
    addop_macro3 'test',11	# 'bit'
    addop_macro3 'andn',12	# 'bic'
    addop_macro3 'or',  13	# 'bis'
    addop_macro3 'xor', 14
    addop_macro3 'and', 15
  end

  def addop_macro1(name, bin, *props)
    if props.delete :byte
      addop_byte name, (0b000100 << 10) | (bin << 7), :as, :rd, *props
    else
      addop name, (0b000100 << 10) | (bin << 7), :as, :rd, *props
    end
  end

  def addop_macro2(name, bin, *props)
    addop name, (0b001 << 13) | (bin << 10), :joff, :setip, *props
  end

  def addop_macro3(name, bin, *props)
    addop_byte name, (bin << 12), :r_pc, :ad, :as, :rs, :setip, :stopexec	# dst == pc
    addop_byte name, (bin << 12), :rd, :ad, :as, :rs
  end

  def addop_byte(name, bin, *props)
    addop name, bin, *props
    addop name + '.b', bin | (1 << 6), :byte, *props
  end
end
end
