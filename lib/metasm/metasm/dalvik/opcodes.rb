#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# the Dalvik binary format, aka android java backend bytecode
# this file was generated using the android source tree, as reference,
# specifically dalvik/libdex/InstrUtils.c

# the binary opcode format is 16 bit word-based
# the opcode number is in the low-order byte, and determines the
# argument format, which may take up to 4 other words

require 'metasm/dalvik/main'

module Metasm
class Dalvik
	OPCODES = %w[nop move move_from16 move_16 move_wide move_wide_from16
move_wide_16 move_object move_object_from16 move_object_16 move_result
move_result_wide move_result_object move_exception
return_void return return_wide return_object
const_4 const_16 const const_high16 const_wide_16 const_wide_32
const_wide const_wide_high16 const_string const_string_jumbo const_class
monitor_enter monitor_exit check_cast instance_of array_length
new_instance new_array filled_new_array filled_new_array_range fill_array_data
throw goto goto_16 goto_32 packed_switch sparse_switch
cmpl_float cmpg_float cmpl_double cmpg_double cmp_long
if_eq if_ne if_lt if_ge if_gt if_le if_eqz if_nez if_ltz if_gez if_gtz if_lez
unused_3e unused_3f unused_40 unused_41 unused_42 unused_43
aget aget_wide aget_object aget_boolean aget_byte aget_char aget_short
aput aput_wide aput_object aput_boolean aput_byte aput_char aput_short
iget iget_wide iget_object iget_boolean iget_byte iget_char iget_short
iput iput_wide iput_object iput_boolean iput_byte iput_char iput_short
sget sget_wide sget_object sget_boolean sget_byte sget_char sget_short
sput sput_wide sput_object sput_boolean sput_byte sput_char sput_short
invoke_virtual invoke_super invoke_direct invoke_static invoke_interface
unused_73
invoke_virtual_range invoke_super_range invoke_direct_range invoke_static_range invoke_interface_range
unused_79 unused_7a
neg_int not_int neg_long not_long neg_float neg_double
int_to_long int_to_float int_to_double long_to_int long_to_float long_to_double
float_to_int float_to_long float_to_double double_to_int double_to_long
double_to_float int_to_byte int_to_char int_to_short
add_int sub_int mul_int div_int rem_int and_int or_int xor_int shl_int shr_int ushr_int
add_long sub_long mul_long div_long rem_long and_long or_long xor_long shl_long shr_long ushr_long
add_float sub_float mul_float div_float rem_float
add_double sub_double mul_double div_double rem_double
add_int_2addr sub_int_2addr mul_int_2addr div_int_2addr rem_int_2addr
and_int_2addr or_int_2addr xor_int_2addr shl_int_2addr shr_int_2addr ushr_int_2addr
add_long_2addr sub_long_2addr mul_long_2addr div_long_2addr rem_long_2addr
and_long_2addr or_long_2addr xor_long_2addr shl_long_2addr shr_long_2addr ushr_long_2addr
add_float_2addr sub_float_2addr mul_float_2addr div_float_2addr rem_float_2addr
add_double_2addr sub_double_2addr mul_double_2addr div_double_2addr rem_double_2addr
add_int_lit16 rsub_int mul_int_lit16 div_int_lit16 rem_int_lit16 and_int_lit16 or_int_lit16 xor_int_lit16
add_int_lit8 rsub_int_lit8 mul_int_lit8 div_int_lit8 rem_int_lit8 and_int_lit8 or_int_lit8 xor_int_lit8
shl_int_lit8 shr_int_lit8 ushr_int_lit8
unused_e3 unused_e4 unused_e5 unused_e6 unused_e7 unused_e8 unused_e9 unused_ea unused_eb unused_ec
throw_verification_error execute_inline unused_ef invoke_direct_empty unused_f1
iget_quick iget_wide_quick iget_object_quick iput_quick iput_wide_quick iput_object_quick
invoke_virtual_quick invoke_virtual_quick_range invoke_super_quick invoke_super_quick_range
unused_fc unused_fd unused_fe unused_ff]

	def init_dalvik
		@valid_props << :canthrow
		@valid_args = [:i16, :i16_32hi, :i16_64hi, :i32, :iaa, :ib, :icc, :u16, :u32, :u64,
			:r16, :ra, :raa, :rb, :rbb, :rcc, :rlist16, :rlist4, :rlist5, :m16]
		@opcode_list = []

		OPCODES.each_with_index { |n, b|
			op = Opcode.new(n, b)
			addop_args(op)
			addop_props(op)
			@opcode_list << op
		}

		raise "Internal error #{@opcode_list.length}" if @opcode_list.length != 256
	end
	alias init_latest init_dalvik

	def addop_args(op)
		fmt = case op.name
		when 'goto'
  			:fmt10t
		when 'nop', 'return_void'
			:fmt10x
		when 'const_4'
			:fmt11n
		when 'const_high16'
			:fmt21h
		when 'const_wide_high16'
			:fmt21hh
		when 'move_result', 'move_result_wide', 'move_result_object',
			'move_exception', 'return', 'return_wide',
			'return_object', 'monitor_enter', 'monitor_exit',
			'throw'
			:fmt11x
		when 'move', 'move_wide', 'move_object', 'array_length',
			'neg_int', 'not_int', 'neg_long', 'not_long',
			'neg_float', 'neg_double', 'int_to_long',
			'int_to_float', 'int_to_double', 'long_to_int',
			'long_to_float', 'long_to_double', 'float_to_int',
			'float_to_long', 'float_to_double', 'double_to_int',
			'double_to_long', 'double_to_float', 'int_to_byte',
			'int_to_char', 'int_to_short', 'add_int_2addr',
			'sub_int_2addr', 'mul_int_2addr', 'div_int_2addr',
			'rem_int_2addr', 'and_int_2addr', 'or_int_2addr',
			'xor_int_2addr', 'shl_int_2addr', 'shr_int_2addr',
			'ushr_int_2addr', 'add_long_2addr', 'sub_long_2addr',
			'mul_long_2addr', 'div_long_2addr', 'rem_long_2addr',
			'and_long_2addr', 'or_long_2addr', 'xor_long_2addr',
			'shl_long_2addr', 'shr_long_2addr', 'ushr_long_2addr',
			'add_float_2addr', 'sub_float_2addr', 'mul_float_2addr',
			'div_float_2addr', 'rem_float_2addr',
			'add_double_2addr', 'sub_double_2addr',
			'mul_double_2addr', 'div_double_2addr',
			'rem_double_2addr'
			:fmt12x
		when 'goto_16'
			:fmt20t
		when 'goto_32'
			:fmt30t
		when 'const_string', 'const_class', 'check_cast',
			'new_instance', 'sget', 'sget_wide', 'sget_object',
			'sget_boolean', 'sget_byte', 'sget_char', 'sget_short',
			'sput', 'sput_wide', 'sput_object', 'sput_boolean',
			'sput_byte', 'sput_char', 'sput_short'
			:fmt21c
		when 'const_16', 'const_wide_16'
			:fmt21s
		when 'if_eqz', 'if_nez', 'if_ltz', 'if_gez', 'if_gtz', 'if_lez'
			:fmt21t
		when 'fill_array_data', 'packed_switch', 'sparse_switch'
			:fmt31t
		when 'add_int_lit8', 'rsub_int_lit8', 'mul_int_lit8',
			'div_int_lit8', 'rem_int_lit8', 'and_int_lit8',
			'or_int_lit8', 'xor_int_lit8', 'shl_int_lit8',
			'shr_int_lit8', 'ushr_int_lit8'
			:fmt22b
		when 'instance_of', 'new_array', 'iget', 'iget_wide',
			'iget_object', 'iget_boolean', 'iget_byte',
			'iget_char', 'iget_short', 'iput', 'iput_wide',
			'iput_object', 'iput_boolean', 'iput_byte',
			'iput_char', 'iput_short'
			:fmt22c
		when 'add_int_lit16', 'rsub_int', 'mul_int_lit16',
			'div_int_lit16', 'rem_int_lit16', 'and_int_lit16',
			'or_int_lit16', 'xor_int_lit16'
			:fmt22s
		when 'if_eq', 'if_ne', 'if_lt', 'if_ge', 'if_gt', 'if_le'
			:fmt22t
		when 'move_from16', 'move_wide_from16', 'move_object_from16'
			:fmt22x
		when 'cmpl_float', 'cmpg_float', 'cmpl_double', 'cmpg_double',
			'cmp_long', 'aget', 'aget_wide', 'aget_object',
			'aget_boolean', 'aget_byte', 'aget_char', 'aget_short',
			'aput', 'aput_wide', 'aput_object', 'aput_boolean',
			'aput_byte', 'aput_char', 'aput_short', 'add_int',
			'sub_int', 'mul_int', 'div_int', 'rem_int', 'and_int',
			'or_int', 'xor_int', 'shl_int', 'shr_int', 'ushr_int',
			'add_long', 'sub_long', 'mul_long', 'div_long',
			'rem_long', 'and_long', 'or_long', 'xor_long',
			'shl_long', 'shr_long', 'ushr_long', 'add_float',
			'sub_float', 'mul_float', 'div_float', 'rem_float',
			'add_double', 'sub_double', 'mul_double', 'div_double',
			'rem_double'
			:fmt23x
		when 'const', 'const_wide_32'
			:fmt31i
		when 'const_string_jumbo'
			:fmt31c
		when 'move_16', 'move_wide_16', 'move_object_16'
			:fmt32x
		when 'filled_new_array'
			:fmt35ca
		when 'invoke_virtual', 'invoke_super',
			'invoke_direct', 'invoke_static', 'invoke_interface'
			:fmt35c
		when 'filled_new_array_range', 'invoke_virtual_range',
			'invoke_super_range', 'invoke_direct_range',
			'invoke_static_range', 'invoke_interface_range'
			:fmt3rc
		when 'const_wide'
			:fmt51l
		when 'throw_verification_error'
			:fmt20bc
		when 'iget_quick', 'iget_wide_quick', 'iget_object_quick',
			'iput_quick', 'iput_wide_quick', 'iput_object_quick'
			:fmt22cs
		when 'invoke_virtual_quick', 'invoke_super_quick'
			:fmt35ms
		when 'invoke_virtual_quick_range', 'invoke_super_quick_range'
			:fmt3rms
		when 'execute_inline'
			:fmt3inline
		when 'invoke_direct_empty'
			:fmt35c
		when 'unused_3e', 'unused_3f', 'unused_40', 'unused_41',
			'unused_42', 'unused_43', 'unused_73', 'unused_79',
			'unused_7a', 'unused_e3', 'unused_e4', 'unused_e5',
			'unused_e6', 'unused_e7', 'unused_e8', 'unused_e9',
			'unused_ea', 'unused_eb', 'unused_ec', 'unused_ef',
			'unused_f1', 'unused_fc', 'unused_fd', 'unused_fe',
			'unused_ff'
			:fmtUnknown
		else
			raise "Internal error #{op.name}"
		end

		case fmt
		when :fmt10x; op.args << :iaa
		when :fmt12x; op.args << :ra << :rb
		when :fmt11n; op.args << :ra << :ib
		when :fmt11x; op.args << :raa
		when :fmt10t; op.args << :iaa
		when :fmt20t; op.args << :i16
		when :fmt20bc; op.args << :iaa << :u16
		when :fmt21c; op.args << :raa << :u16
		when :fmt22x; op.args << :raa << :r16
		when :fmt21s, :fmt21t; op.args << :raa << :i16
		when :fmt21h; op.args << :raa << :i16_32hi
		when :fmt21hh; op.args << :raa << :i16_64hi
		when :fmt23x; op.args << :raa << :rbb << :rcc
		when :fmt22b; op.args << :raa << :rbb << :icc
		when :fmt22s, :fmt22t; op.args << :ra << :rb << :i16
		when :fmt22c, :fmt22cs; op.args << :ra << :rb << :u16
		when :fmt30t; op.args << :i32
		when :fmt31t, :fmt31c; op.args << :raa << :u32
		when :fmt32x; op.args << :r16 << :r16
		when :fmt31i; op.args << :raa << :i32
		when :fmt35ca
			op.args << :r16 << :rlist5
		when :fmt35c, :fmt35ms
			# rlist:
			#  nr of regs in :ib (max 5)
			#  regs: :ib.times { reg :i16 & 0xf ; :i16 >>= 4 }
			#  reg :ra if :ib == 5
			op.args << :m16 << :rlist5
		when :fmt3inline
			op.args << :r16 << :rlist4
		when :fmt3rc, :fmt3rms
		       	# rlist = :r16, :r16+1, :r16+2, ..., :r16+:iaa-1
			op.args << :r16 << :rlist16
		when :fmt51l
			# u64 = u16 | (u16 << 16) | ...
			op.args << :raa << :u64
		when :fmtUnknown
			op.args << :iaa
		else
			raise "Internal error #{fmt.inspect}"
		end
	end

	def addop_props(op)
		case op.name
		when 'nop', 'move', 'move_from16', 'move_16', 'move_wide',
			'move_wide_from16', 'move_wide_16', 'move_object',
			'move_object_from16', 'move_object_16', 'move_result',
			'move_result_wide', 'move_result_object',
			'move_exception', 'const_4', 'const_16', 'const',
			'const_high16', 'const_wide_16', 'const_wide_32',
			'const_wide', 'const_wide_high16', 'fill_array_data',
			'cmpl_float', 'cmpg_float', 'cmpl_double',
			'cmpg_double', 'cmp_long', 'neg_int', 'not_int',
			'neg_long', 'not_long', 'neg_float', 'neg_double',
			'int_to_long', 'int_to_float', 'int_to_double',
			'long_to_int', 'long_to_float', 'long_to_double',
			'float_to_int', 'float_to_long', 'float_to_double',
			'double_to_int', 'double_to_long', 'double_to_float',
			'int_to_byte', 'int_to_char', 'int_to_short', 'add_int',
			'sub_int', 'mul_int', 'and_int', 'or_int', 'xor_int',
			'shl_int', 'shr_int', 'ushr_int', 'add_long',
			'sub_long', 'mul_long', 'and_long', 'or_long',
			'xor_long', 'shl_long', 'shr_long', 'ushr_long',
			'add_float', 'sub_float', 'mul_float', 'div_float',
			'rem_float', 'add_double', 'sub_double', 'mul_double',
			'div_double', 'rem_double', 'add_int_2addr',
			'sub_int_2addr', 'mul_int_2addr', 'and_int_2addr',
			'or_int_2addr', 'xor_int_2addr', 'shl_int_2addr',
			'shr_int_2addr', 'ushr_int_2addr', 'add_long_2addr',
			'sub_long_2addr', 'mul_long_2addr', 'and_long_2addr',
			'or_long_2addr', 'xor_long_2addr', 'shl_long_2addr',
			'shr_long_2addr', 'ushr_long_2addr', 'add_float_2addr',
			'sub_float_2addr', 'mul_float_2addr', 'div_float_2addr',
			'rem_float_2addr', 'add_double_2addr',
			'sub_double_2addr', 'mul_double_2addr',
			'div_double_2addr', 'rem_double_2addr', 'add_int_lit16',
			'rsub_int', 'mul_int_lit16', 'and_int_lit16',
			'or_int_lit16', 'xor_int_lit16', 'add_int_lit8',
			'rsub_int_lit8', 'mul_int_lit8', 'and_int_lit8',
			'or_int_lit8', 'xor_int_lit8', 'shl_int_lit8',
			'shr_int_lit8', 'ushr_int_lit8'
			# normal opcode, continues to next, nothing raised
		when 'const_string', 'const_string_jumbo', 'const_class',
			'monitor_enter', 'monitor_exit', 'check_cast',
			'instance_of', 'array_length', 'new_instance',
			'new_array', 'filled_new_array',
			'filled_new_array_range', 'aget', 'aget_boolean',
			'aget_byte', 'aget_char', 'aget_short', 'aget_wide',
			'aget_object', 'aput', 'aput_boolean', 'aput_byte',
			'aput_char', 'aput_short', 'aput_wide', 'aput_object',
			'iget', 'iget_boolean', 'iget_byte', 'iget_char',
			'iget_short', 'iget_wide', 'iget_object', 'iput',
			'iput_boolean', 'iput_byte', 'iput_char', 'iput_short',
			'iput_wide', 'iput_object', 'sget', 'sget_boolean',
			'sget_byte', 'sget_char', 'sget_short', 'sget_wide',
			'sget_object', 'sput', 'sput_boolean', 'sput_byte',
			'sput_char', 'sput_short', 'sput_wide', 'sput_object',
			'div_int', 'rem_int', 'div_long', 'rem_long',
			'div_int_2addr', 'rem_int_2addr', 'div_long_2addr',
			'rem_long_2addr', 'div_int_lit16', 'rem_int_lit16',
			'div_int_lit8', 'rem_int_lit8'
			op.props[:canthrow] = true
		when 'invoke_virtual', 'invoke_virtual_range', 'invoke_super',
			'invoke_super_range', 'invoke_direct',
			'invoke_direct_range', 'invoke_static',
			'invoke_static_range', 'invoke_interface',
			'invoke_interface_range'
			op.props[:canthrow] = true
			op.props[:saveip] = true
			op.props[:setip] = true
			op.props[:stopexec] = true
		when 'return_void', 'return', 'return_wide', 'return_object'
			op.props[:setip] = true
			op.props[:stopexec] = true
		when 'throw'
			op.props[:canthrow] = true
			op.props[:stopexec] = true
		when 'goto', 'goto_16', 'goto_32'
			op.props[:setip] = true
			op.props[:stopexec] = true
		when 'if_eq', 'if_ne', 'if_lt', 'if_ge', 'if_gt', 'if_le',
			'if_eqz', 'if_nez', 'if_ltz', 'if_gez', 'if_gtz',
			'if_lez'
			op.props[:setip] = true
		when 'packed_switch', 'sparse_switch'
			op.props[:setip] = true	# if no table match, nostopexec
			op.props[:setip] = true
		when 'throw_verification_error'
			op.props[:canthrow] = true
			op.props[:stopexec] = true
		when 'execute_inline'
		when 'iget_quick', 'iget_wide_quick', 'iget_object_quick',
			'iput_quick', 'iput_wide_quick', 'iput_object_quick'
			op.props[:canthrow] = true
		when 'invoke_virtual_quick', 'invoke_virtual_quick_range',
			'invoke_super_quick', 'invoke_super_quick_range',
			'invoke_direct_empty'
			op.props[:canthrow] = true
			op.props[:saveip] = true
			op.props[:setip] = true
			op.props[:stopexec] = true
		when 'unused_3e', 'unused_3f', 'unused_40', 'unused_41',
			'unused_42', 'unused_43', 'unused_73', 'unused_79',
			'unused_7a', 'unused_e3', 'unused_e4', 'unused_e5',
			'unused_e6', 'unused_e7', 'unused_e8', 'unused_e9',
			'unused_ea', 'unused_eb', 'unused_ec', 'unused_ef',
			'unused_f1', 'unused_fc', 'unused_fd', 'unused_fe',
			'unused_ff'
			op.props[:stopexec] = true
		else
			raise "Internal error #{op.name}"
		end
	end
end
end

