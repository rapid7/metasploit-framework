#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2015-2016 Google
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/cpu/mcs51/opcodes'
require 'metasm/decode'

module Metasm
class MCS51

	def build_opcode_bin_mask(op)
		op.bin_mask = 0
		op.fields.each { |f, off|
			op.bin_mask |= (@fields_mask[f] << off)
		}
		op.bin_mask ^= 0xff
	end

	def build_bin_lookaside
		lookaside = Array.new(256) { [] }
		opcode_list.each { |op|
			build_opcode_bin_mask op
			b   = op.bin
			msk = op.bin_mask
			for i in b..(b | (255^msk))
				lookaside[i] << op if i & msk == b & msk
			end
		}
		lookaside
	end

	def decode_findopcode(edata)
		di = DecodedInstruction.new self
		byte = edata.data[edata.ptr]
		byte = byte.unpack('C').first if byte.kind_of?(::String)
		if not byte
			return
		end
		return di if di.opcode = @bin_lookaside[byte].find { |op|
			byte & op.bin_mask == op.bin & op.bin_mask
		}
	end

	def decode_instr_op(edata, di)
		before_ptr = edata.ptr
		op = di.opcode
		di.instruction.opname = op.name
		bseq = edata.get_byte

		field_val = lambda { |f|
			if fld = op.fields[f]
				(bseq >> fld) & @fields_mask[f]
			end
		}

		op.args.each { |a|
			di.instruction.args << case a
			when :rel8
				Expression[edata.decode_imm(:i8, @endianness)]
			when :d8
				Immediate.new(edata.decode_imm(:u8, @endianness))
			when :m8
				Memref.new(nil, edata.decode_imm(:u8, @endianness))
			when :rd
				if (field_val[a] & 0b1110) == 0b0110
					Memref.new(Reg.new(field_val[a] + 2), nil)
				else
					Reg.new(field_val[a])
				end
			when :r_a
				Reg.from_str('A')
			when :r_b
				Reg.from_str('B')
			when :r_c
				Reg.from_str('C')
			when :addr_11
				Memref.new(nil, edata.decode_imm(:u8, @endianness))
			when :addr_16
				Memref.new(nil, edata.decode_imm(:u16, @endianness))
			end
		}

		di.bin_length += edata.ptr - before_ptr

		di
	end

	def backtrace_binding(b)
		@backtrace_binding ||= {}
	end

	def get_xrefs_x(b,c)
		[]
	end

end
end
