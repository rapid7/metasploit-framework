#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/arm/opcodes'
require 'metasm/encode'

module Metasm
class ARM
	def encode_instr_op(section, instr, op)
		base = op.bin
		set_field = lambda { |f, v|
			case f
			when :i8_12
				base |= (v & 0xf) | ((v << 4) & 0xf00)
				next
			when :stype; v = [:lsl, :lsr, :asr, :ror].index(v)
			when :u; v = [:-, :+].index(v)
			end
			base |= (v & @fields_mask[f]) << @fields_shift[f]
		}

		val, mask, shift = 0, 0, 0

		if op.props[:cond]
			coff = op.props[:cond_name_off] || op.name.length
			cd = instr.opname[coff, 2]
			cdi = %w[eq ne cs cc mi pl vs vc hi ls ge lt gt le al].index(cd) || 14	# default = al
			set_field[:cond, cdi]
		end

		op.args.zip(instr.args).each { |sym, arg|
			case sym
			when :rd, :rs, :rn, :rm; set_field[sym, arg.i]
			when :rm_rs
				set_field[:rm, arg.i]
				set_field[:stype, arg.stype]
				set_field[:rs, arg.shift.i]
			when :rm_is
				set_field[:rm, arg.i]
				set_field[:stype, arg.stype]
				set_field[:shifti, arg.shift/2]
			when :mem_rn_rm, :mem_rn_rms, :mem_rn_i8_12, :mem_rn_i12
				set_field[:rn, arg.base.i]
				case sym
				when :mem_rn_rm
					set_field[:rm, arg.off.i]
				when :mem_rn_rms
					set_field[:rm, arg.off.i]
					set_field[:stype, arg.off.stype]
					set_field[:rs, arg.off.shift.i]
				when :mem_rn_i8_12
					set_field[:i8_12, arg.off]
				when :mem_rn_i12
					set_field[:i12, arg.off]
				end
				# TODO set_field[:u] etc
			when :reglist
				set_field[sym, arg.list.inject(0) { |rl, r| rl | (1 << r.i) }]
			when :i8_r
				# XXX doublecheck this
				b = arg.reduce & 0xffffffff
				r = (0..15).find { next true if b < 0x10 ; b = (b >> 2) | ((b & 3) << 30) }
				set_field[:i8, b]
				set_field[:rotate, r]
			when :i16, :i24
				val, mask, shift = arg, @fields_mask[sym], @fields_shift[sym]
			end
		}

		Expression[base, :|, [[val, :<<, shift], :&, mask]].encode(:u32, @endianness)
	end
end
end
