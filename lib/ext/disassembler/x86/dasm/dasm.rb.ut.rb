#!/usr/bin/env ruby

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', '..'))

require 'test/unit'
require 'ext/disassembler/x86'
require 'ext/disassembler/x86/dasm/dasm'

class Ext::Disassembler::X86::Dasm::UnitTest < Test::Unit::TestCase
	Klass = Ext::Disassembler::X86::Dasm
	X86 = Ext::Disassembler::X86

	def test_mode
		d = Klass.new

		assert_equal(32, d.mode)
		assert_equal(true, d.set_mode(16))
		assert_equal(16, d.mode)
		assert_equal(true, d.set_mode(32))
		assert_equal(32, d.mode)
	end

	def test_disassemble
		d   = Klass.new
		b1  = "\x41"
		ary = d.disassemble(b1)

		assert_not_nil(ary)

		inst = ary[0]

		assert_not_nil(inst)
		assert_kind_of(Ext::Disassembler::X86::Dasm::Instruction, inst)
		assert_equal(1, inst.length)
		assert_equal(Klass::Instruction::Type::INC, inst.type)
		assert_equal(32, inst.mode)
		assert_equal(0x41, inst.opcode)
		assert_nil(inst.modrm)
		assert_nil(inst.sib)
		assert_equal(0, inst.dispbytes)
		assert_equal(0, inst.immbytes)
		assert_equal(0, inst.sectionbytes)
		assert_equal("\x41", inst.raw)
		assert_equal("inc ecx", inst.to_s);
		d.set_format("att")
		assert_equal("inc %ecx", inst.to_s);
		assert_equal(X86::EFL_OF | X86::EFL_SF | X86::EFL_ZF | X86::EFL_AF | X86::EFL_PF, inst.eflags_affected)
	end

	def test_operand
		d   = Klass.new
		b1  = "\xc7\x44\x24\x04\x78\x56\x34\x12\x41"
		ary = d.disassemble(b1)

		assert_not_nil(ary)
		
		inst1 = ary[0]
		inst2 = ary[1]

		# inst1: mov dword [esp+0x4],0x12345678
		assert_not_nil(inst1.op1)
		assert_not_nil(inst1.op2)
		assert_nil(inst1.op3)
		assert_equal(Ext::Disassembler::X86::Operand::Type::Memory, inst1.op1.type)
		assert_equal(Ext::Disassembler::X86::Operand::Type::Immediate, inst1.op2.type)
		assert_equal(Ext::Disassembler::X86::Register::ESP, inst1.op1.basereg)
		assert_equal(4, inst1.op1.displacement)
		assert_equal(0x12345678, inst1.op2.immediate)
		assert_equal("mov dword [esp+0x4],0x12345678", inst1.to_s)

		# inst2: inc ecx
		assert_not_nil(inst2.op1)
		assert_nil(inst2.op2)
		assert_nil(inst2.op3)
		assert_equal(Ext::Disassembler::X86::Register::ECX, inst2.op1.reg)
		assert_equal(Ext::Disassembler::X86::Register::Type::General, inst2.op1.regtype)
	end

end
