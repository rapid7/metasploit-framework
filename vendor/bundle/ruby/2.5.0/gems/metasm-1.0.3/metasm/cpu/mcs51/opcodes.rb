#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2015-2016 Google
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/cpu/mcs51/main'

module Metasm

class MCS51
	def addop(name, bin, *args)
		o = Opcode.new name, bin
		args.each { |a|
			o.args << a if @fields_mask[a] or @valid_args[a]
			o.fields[a] = @fields_shift[a] if @fields_mask[a]
			raise "unknown #{a.inspect}" unless @valid_args[a] or @fields_mask[a]
		}
		@opcode_list << o
	end

	def init_mcs51
		@opcode_list = []
		@valid_args.update [:rd, :r_a, :r_b, :r_c, :d8, :rel8, :m8,
		                    :addr_11, :addr_16].inject({}) { |h, v| h.update v => true }
		@fields_mask.update :rd => 15, :addr_11 => 7
		@fields_shift.update :rd => 0, :addr_11 => 5

		addop 'nop',   0x00
		addop 'ret',   0x22
		addop 'reti',  0x32
		addop 'swap',  0xc4, :r_a
		addop '???',   0xa5
		addop 'rr',    0x03, :r_a
		addop 'rrc',   0x13, :r_a
		addop 'rl',    0x23, :r_a
		addop 'rlc',   0x33, :r_a

		addop 'jc',    0x40, :rel8
		addop 'jnc',   0x50, :rel8
		addop 'jz',    0x60, :rel8
		addop 'jnz',   0x70, :rel8
		addop 'sjmp',  0x80, :rel8

		addop 'div',   0x84, :r_a, :r_b
		addop 'mul',   0xa4, :r_a, :r_b

		addop 'push',  0xc0, :m8
		addop 'pop',   0xd0, :m8

		addop 'clr',   0xc3, :r_c
		addop 'clr',   0xe4, :r_a
		addop 'cpl',   0xb3, :r_c
		addop 'cpl',   0xf4, :r_a
		addop 'da',    0xd4

		addop 'ajmp',  0x01, :addr_11
		addop 'acall', 0x11, :addr_11
		addop 'ljmp',  0x02, :addr_16
		addop 'lcall', 0x12, :addr_16

		addop 'inc',   0x04, :r_a
		addop 'inc',   0x05, :m8
		addop 'inc',   0x00, :rd

		addop 'dec',   0x14, :r_a
		addop 'dec',   0x15, :m8
		addop 'dec',   0x10, :rd

		addop 'add',   0x24, :r_a, :d8
		addop 'add',   0x25, :r_a, :m8
		addop 'add',   0x20, :r_a, :rd

		addop 'addc',  0x34, :r_a, :d8
		addop 'addc',  0x35, :r_a, :m8
		addop 'addc',  0x30, :r_a, :rd

		addop 'orl',   0x42, :m8, :r_a
		addop 'orl',   0x43, :m8, :d8
		addop 'orl',   0x44, :r_a, :d8
		addop 'orl',   0x45, :r_a, :m8
		addop 'orl',   0x40, :r_a, :rd

		addop 'anl',   0x52, :m8, :r_a
		addop 'anl',   0x53, :m8, :d8
		addop 'anl',   0x54, :r_a, :d8
		addop 'anl',   0x55, :r_a, :m8
		addop 'anl',   0x50, :r_a, :rd

		addop 'xrl',   0x62, :m8, :r_a
		addop 'xrl',   0x63, :m8, :d8
		addop 'xrl',   0x64, :r_a, :d8
		addop 'xrl',   0x65, :r_a, :m8
		addop 'xrl',   0x60, :r_a, :rd

		addop 'mov',   0x74, :r_a, :d8
		addop 'mov',   0x75, :m8, :d8
		addop 'mov',   0x70, :rd, :d8
		addop 'mov',   0xa0, :rd, :m8
		addop 'mov',   0x85, :m8, :m8
		addop 'mov',   0x80, :m8, :rd
		addop 'mov',   0xe0, :r_a, :rd
		addop 'mov',   0xf0, :rd, :r_a

		addop 'subb',  0x94, :r_a, :d8
		addop 'subb',  0x95, :r_a, :m8
		addop 'subb',  0x90, :r_a, :rd

		addop 'cnje',  0xb4, :r_a, :d8, :rel8
		addop 'cnje',  0xb5, :r_a, :m8, :rel8
		addop 'cnje',  0xb0, :rd, :d8, :rel8

		addop 'xch',   0xc5, :r_a, :m8
		addop 'xch',   0xc0, :r_a, :rd

		addop 'djnz',  0xd5, :m8, :rel8
		addop 'djnz',  0xd0, :rd, :rel8

	end
end
end
