#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'test/unit'
require 'metasm'

class TestPreproc < Test::Unit::TestCase
	include Metasm

	def asm_dasm(src)
		@cpu ||= Ia32.new
		raw = Shellcode.assemble(src, @cpu).encode_string
		dasm = Shellcode.decode(raw, @cpu).disassembler
		dasm.disassemble_fast(0)
		dasm
	end

	def do_test_bd2(src, bd)
		d = asm_dasm(src)
		calc_bd = d.compose_bt_binding(*d.decoded[0].block.list)
		calc_bd.delete_if { |k, v| k.to_s =~ /flag/ }
		assert_equal bd, calc_bd
	end

	def test_compose_bt_binding
		do_test_bd2 'mov eax, 1  mov ebx, 2', :eax => Expression[1], :ebx => Expression[2]
		do_test_bd2 'mov eax, 1  push eax', :eax => Expression[1], Indirection[:esp, 4] => Expression[1], :esp => Expression[:esp, :+, -4]
		do_test_bd2 'mov [eax], ebx  mov [eax], ecx', Indirection[:eax, 4] => Expression[:ecx]
		do_test_bd2 'add eax, 4  mov [eax], ecx', Indirection[:eax, 4] => Expression[:ecx], :eax => Expression[:eax, :+, 4]
		do_test_bd2 'mov [eax], ecx  mov ebx, eax', :ebx => Expression[:eax], Indirection[:eax, 4] => Expression[:ecx], Indirection[:ebx, 4] => Expression[:ecx]
		do_test_bd2 'mov [eax], ecx  add eax, 4', :eax => Expression[:eax, :+, 4], Indirection[[:eax, :+, -4], 4] => Expression[:ecx]
		do_test_bd2 'mov [eax+4], ecx  add eax, 4', :eax => Expression[:eax, :+, 4], Indirection[:eax, 4] => Expression[:ecx]
		do_test_bd2 'push 1  push 2', :esp => Expression[:esp, :+, -8], Indirection[:esp, 4] => Expression[2], Indirection[[:esp, :+, 4], 4] => Expression[1]
	end
end

