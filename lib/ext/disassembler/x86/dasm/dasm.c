//
// Wraps jt's libdasm in ruby classes that can be accessed through:
//
// Ext::Disassembler::X86::Dasm
// Ext::Disassembler::X86::Dasm::Instruction
// Ext::Disassembler::X86::Dasm::Operand
//
// Example:
//
// dasm = Ext::Disassembler::X86::Dasm.new
//
// dasm.disassemble(buf).each { |instruction|
// 	puts instruction.to_s
// }
//
// All credits for the disassembler go to jt <jt at klake.org> :)
//
// skape
// 01/2006
//
#include <stdlib.h>
#include <stdio.h>
#include <ruby.h>
#include "libdasm.h"

#define min(x, y) (x < y) ? x : y

static VALUE dasm_klass;
static VALUE instr_klass;
static VALUE instr_type_klass;
static VALUE oper_klass;
static VALUE oper_type_klass;

typedef struct _DASM_OBJECT
{
	enum Mode   mode;
	enum Format format;
} DASM_OBJECT, *PDASM_OBJECT;

#define rb_dasm_cast(x, y) \
	Data_Get_Struct(x, DASM_OBJECT, y)

////
//
// Operand class
//
////

typedef struct _OPERAND_OBJECT
{
	OPERAND *op;
} OPERAND_OBJECT, *POPERAND_OBJECT;

#define rb_operand_cast(x, y) \
	Data_Get_Struct(x, OPERAND_OBJECT, y)	

//
// Deallocates the memory used by an instance of the operand class.
//
static void operand_free(void *oper)
{
	if (oper)
		free(oper);
}

//
// Allocates storage for the operand instance structure.
//
static VALUE operand_alloc(VALUE klass)
{
	POPERAND_OBJECT oper;
	VALUE           obj;

	obj = Data_Make_Struct(klass, OPERAND_OBJECT, 0, operand_free, oper);

	oper->op = NULL;

	return obj;
}

//
// Allocates and initializes an instance of the Operand class.
//
static VALUE operand_new(VALUE klass, OPERAND *op)
{
	POPERAND_OBJECT oper;
	VALUE           obj = operand_alloc(klass);

	rb_operand_cast(obj, oper);

	oper->op = op;

	return obj;
}

//
// Returns the operands type as one of the Ext::Disassembler::X86::Operand::Type
// constants.
//
static VALUE operand_type(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(get_operand_type(oper->op));
}

//
// Returns the register used by the operand, if any, as one of the
// Ext::Disassembler::X86::Register constants.
//
static VALUE operand_reg(VALUE self)
{
	POPERAND_OBJECT oper;
	VALUE    rv;

	rb_operand_cast(self, oper);

	if (get_operand_register(oper->op) == REGISTER_NOP)
		rv = Qnil;
	else
		rv = INT2FIX(get_operand_register(oper->op));

	return rv;
}

//
// Returns the register type being used by the operand, if any, as one of the
// Ext::Disassembler::X86::Register::Type constants.
//
static VALUE operand_regtype(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(get_register_type(oper->op));
}

//
// Returns the base register that is used when the operand is a memory operand.
//
static VALUE operand_basereg(VALUE self)
{
	POPERAND_OBJECT oper;
	VALUE           rv;

	rb_operand_cast(self, oper);

	return (oper->op->basereg == REGISTER_NOP) ? Qnil : INT2FIX(oper->op->basereg);
}

//
// Returns the index register that is used when the operand is a memory operand.
//
static VALUE operand_indexreg(VALUE self)
{
	POPERAND_OBJECT oper;
	VALUE           rv;

	rb_operand_cast(self, oper);

	return (oper->op->indexreg == REGISTER_NOP) ? Qnil : INT2FIX(oper->op->indexreg);
}

//
// Returns the scale used.
//
static VALUE operand_scale(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(get_operand_scale(oper->op));
}

//
// The number of bytes used for displacement.
//
static VALUE operand_dispbytes(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(oper->op->dispbytes);
}

//
// The offset from the start of the instruction for the displacement bytes.
//
static VALUE operand_dispoffset(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(oper->op->dispoffset);
}

//
// The number of bytes used for immediate data.
//
static VALUE operand_immbytes(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(oper->op->immbytes);
}

//
// The offset from the start of the instruction to the immediate bytes.
//
static VALUE operand_immoffset(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(oper->op->immoffset);
}

//
// The number of bytes used for section.
//
static VALUE operand_sectionbytes(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(oper->op->sectionbytes);
}

//
// The section being used.
//
static VALUE operand_section(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(oper->op->section);
}

//
// The displacement value of the operand, if any.
//
static VALUE operand_displacement(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(oper->op->displacement);
}

//
// The immediate value of the operand, if any.
//
static VALUE operand_immediate(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(oper->op->immediate);
}

//
// Internal flags for the operand.
//
static VALUE operand_flags(VALUE self)
{
	POPERAND_OBJECT oper;

	rb_operand_cast(self, oper);

	return INT2FIX(oper->op->flags);
}

////
//
// Instruction class
//
////

typedef struct _INSTRUCTION_OBJECT
{
	INSTRUCTION inst;
	BYTE        raw[16];
	VALUE       dasm;
	VALUE       op1;
	VALUE       op2;
	VALUE       op3;
} INSTRUCTION_OBJECT, *PINSTRUCTION_OBJECT;

#define rb_instruction_cast(x, y) \
	Data_Get_Struct(x, INSTRUCTION_OBJECT, y)

//
// Deallocates the memory used by an instance of the Instruction class.
//
static void instruction_free(void *inst)
{
	if (inst)
		free(inst);
}

//
// Allocates storage for the Instruction class.
//
static VALUE instruction_alloc(VALUE klass)
{
	PINSTRUCTION_OBJECT inst;
	VALUE               obj;

	obj = Data_Make_Struct(klass, INSTRUCTION_OBJECT, 0, 
		instruction_free, inst);

	return obj;
}

// 
// Creates and initializes an instance of the Instruction class based on the
// supplied INSTRUCTION instance passed from libdasm.
//
static VALUE instruction_new(VALUE klass, VALUE dasm, INSTRUCTION *raw_inst, BYTE *raw)
{
	PINSTRUCTION_OBJECT inst;
	VALUE               obj = instruction_alloc(klass);

	rb_instruction_cast(obj, inst);

	inst->dasm = dasm;

	memcpy(&inst->inst, raw_inst, sizeof(INSTRUCTION));
	memcpy(inst->raw, raw, min(raw_inst->length, sizeof(inst->raw)));

	inst->op1 = (raw_inst->op1.type == OPERAND_TYPE_NONE) ? Qnil : operand_new(oper_klass, &inst->inst.op1);
	inst->op2 = (raw_inst->op2.type == OPERAND_TYPE_NONE) ? Qnil : operand_new(oper_klass, &inst->inst.op2);
	inst->op3 = (raw_inst->op3.type == OPERAND_TYPE_NONE) ? Qnil : operand_new(oper_klass, &inst->inst.op3);

	return obj;
}

//
// Returns the length of the instruction in terms of bytes.
//
static VALUE instruction_length(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return INT2FIX(inst->inst.length);
}

//
// Returns the type of instruction as represented by a constant that can be
// found under the Instruction::Type module.
//
static VALUE instruction_type(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return INT2FIX(inst->inst.type);
}

//
// Returns the addressing mode used when disassembling this instruction.
//
static VALUE instruction_mode(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	VALUE               rv;	
	
	rb_instruction_cast(self, inst);

	switch (inst->inst.mode)
	{
		case MODE_32: rv = INT2FIX(32); break;
		case MODE_16: rv = INT2FIX(16); break;
		default: rv = Qnil; break;
	}

	return rv;
}

//
// Returns the one-byte opcode associated with this instruction.
//
static VALUE instruction_opcode(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return (inst->inst.opcode) ? CHR2FIX(inst->inst.opcode) : Qnil;
}

//
// Returns the Mod R/M byte of the instruction, if any.
//
static VALUE instruction_modrm(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);
	
	return (inst->inst.modrm) ? CHR2FIX(inst->inst.modrm) : Qnil;
}

//
// Returns the SIB byte of the instruction, if any.
//
static VALUE instruction_sib(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return (inst->inst.sib) ? CHR2FIX(inst->inst.sib) : Qnil;
}

//
// Returns the number of displacement bytes used in the instruction.
//
static VALUE instruction_dispbytes(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return INT2FIX(inst->inst.dispbytes);
}

//
// Returns the number of immediate bytes used by the instruction.
//
static VALUE instruction_immbytes(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);
	
	return INT2FIX(inst->inst.immbytes);
}

//
// Returns the number of section bytes used by the instruction.
//
static VALUE instruction_sectionbytes(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return INT2FIX(inst->inst.sectionbytes);
}

// 
// Arbitrary flags used by the disassembler.
//
static VALUE instruction_flags(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return INT2FIX(inst->inst.flags);
}

//
// Returns the raw string associated with the instruction.
//
static VALUE instruction_raw(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return rb_str_new(inst->raw, min(inst->inst.length, sizeof(inst->raw)));
}

//
// Converts the instruction to a printable disassembled string using the format
// that the Dasm instance the instruction came from is using.
//
static VALUE instruction_to_s(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	PDASM_OBJECT        dasm;
	char                buf[32] = { 0 };

	rb_instruction_cast(self, inst);
	rb_dasm_cast(inst->dasm, dasm);

	get_instruction_string(&inst->inst, dasm->format, 0, (BYTE *)buf, sizeof(buf) - 1);

	return rb_str_new2(buf);
}

//
// Returns the first operand of the instruction, if any.
//
static VALUE instruction_op1(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return inst->op1;
}

//
// Returns the second operand of the instruction, if any.
//
static VALUE instruction_op2(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return inst->op2;
}

//
// Returns the third operand of the instruction, if any.
//
static VALUE instruction_op3(VALUE self)
{
	PINSTRUCTION_OBJECT inst;
	
	rb_instruction_cast(self, inst);

	return inst->op3;
}

//
// Returns the eflags that are affected by this instruction.
//
static VALUE instruction_eflags_affected(VALUE self)
{
	PINSTRUCTION_OBJECT inst;

	rb_instruction_cast(self, inst);

	return INT2FIX(inst->inst.eflags_affected);
}

//
// Returns the eflags that are used by this instruction.
//
static VALUE instruction_eflags_used(VALUE self)
{
	PINSTRUCTION_OBJECT inst;

	rb_instruction_cast(self, inst);

	return INT2FIX(inst->inst.eflags_used);
}

////
//
// Dasm class
//
////

//
// Deallocates the memory used by an instance of the Dasm class.
//
static void dasm_free(void *dasm)
{
	if (dasm)
		free(dasm);
}

//
// Initializes the underlying datastructure for an instance of the Dasm class.
//
static VALUE dasm_alloc(VALUE klass)
{
	PDASM_OBJECT dasm;
	VALUE        obj;

	obj = Data_Make_Struct(klass, DASM_OBJECT, 0, dasm_free, dasm);
	dasm->mode   = MODE_32;
	dasm->format = FORMAT_INTEL;

	return obj;
}

//
// Performs a disassembly on the supplied buffer and returns an array of
// Instruction instances.
//
static VALUE dasm_disassemble(VALUE self, VALUE buf)
{
	PDASM_OBJECT obj;
	INSTRUCTION  inst;
	VALUE        instructions = rb_ary_new();
	int          offset = 0, len;
	int          use_block = rb_block_given_p();

	buf = StringValue(buf);
	len = RSTRING(buf)->len;
	
	rb_dasm_cast(self, obj);

	while (offset < len)
	{
		VALUE	rb_inst;
		BYTE  *current = (BYTE *)(RSTRING(buf)->ptr + offset);

		if (!get_instruction(&inst, current, obj->mode))
			break;
		
		rb_inst = instruction_new(instr_klass, self, &inst, current);

		if (!use_block)
		{
			if (!offset)
				instructions = rb_ary_new();
		
			rb_ary_push(instructions, rb_inst);
		}
		else
			rb_yield_values(2, rb_inst, INT2FIX(offset));

		offset += inst.length;
	}

	return (!use_block) ? instructions : offset;
}

//
// Disassembles a single instruction.
//
static VALUE dasm_disassemble_one(VALUE self, VALUE buf)
{
	PDASM_OBJECT obj;
	INSTRUCTION  inst;
	VALUE        rv;
	BYTE         *current;

	buf     = StringValue(buf);
	current = (BYTE *)RSTRING(buf)->ptr;

	rb_dasm_cast(self, obj);
	
	if (!get_instruction(&inst, current, obj->mode))
		rv = Qnil;
	else
		rv = instruction_new(instr_klass, self, &inst, current);

	return rv;
}

//
// Sets the disassembler mode, either 16 or 32 bits.
//
static VALUE dasm_set_mode(VALUE self, VALUE bits)
{
	PDASM_OBJECT obj;
	int          val = FIX2INT(bits);
	
	rb_dasm_cast(self, obj);

	switch (val)
	{
		case 32: obj->mode = MODE_32; break;
		case 16: obj->mode = MODE_16; break;
		default: rb_raise(rb_eArgError, "Invalid disassembler mode (must be 16 or 32)"); break;
	}

	return Qtrue;
}

//
// Returns the current disassembler mode that is being operated under.
//
static VALUE dasm_mode(VALUE self)
{
	PDASM_OBJECT obj;
	VALUE        rv;
	
	rb_dasm_cast(self, obj);

	switch (obj->mode)
	{
		case MODE_32: rv = INT2FIX(32); break;
		case MODE_16: rv = INT2FIX(16); break;
		default: rv = Qnil; break;
	}

	return rv;
}


//
// Changes the format that should be used when displaying disassembly strings.
//
static VALUE dasm_set_format(VALUE self, VALUE format)
{
	PDASM_OBJECT obj;

	format = StringValue(format);

	rb_dasm_cast(self, obj);

	if (!strncasecmp(RSTRING(format)->ptr, "intel", 5))
		obj->format = FORMAT_INTEL;
	else if (!strncasecmp(RSTRING(format)->ptr, "att", 3))
		obj->format = FORMAT_ATT;
	else
		rb_raise(rb_eArgError, "Invalid output format (must be intel or att)");

	return Qnil;
}

//
// Returns the format currently being used when displaying string versions of
// instructions.
//
static VALUE dasm_format(VALUE self)
{
	PDASM_OBJECT obj;
	VALUE        rv;

	rb_dasm_cast(self, obj);

	switch (obj->format)
	{
		case FORMAT_INTEL: rv = rb_str_new2("intel"); break;
		case FORMAT_ATT:   rv = rb_str_new2("att"); break;
		default: rv = Qnil; break;
	}

	return rv;
}

//
// Initializes the dasm classes.
//
void Init_dasm()
{
	// Dasm
	dasm_klass = rb_define_class_under(
		rb_define_module_under(
			rb_define_module_under(
				rb_define_module("Ext"),
				"Disassembler"),
			"X86"),
		"Dasm",
		rb_define_class("Dasm", rb_cObject));

	rb_define_alloc_func(dasm_klass, dasm_alloc);

	rb_define_method(dasm_klass, "disassemble", dasm_disassemble, 1);
	rb_define_method(dasm_klass, "disassemble_one", dasm_disassemble_one, 1);
	rb_define_method(dasm_klass, "set_mode", dasm_set_mode, 1);
	rb_define_method(dasm_klass, "mode", dasm_mode, 0);
	rb_define_method(dasm_klass, "set_format", dasm_set_format, 1);
	rb_define_method(dasm_klass, "format", dasm_format, 0);

	// Instruction
	instr_klass = rb_define_class_under(dasm_klass, "Instruction",
		rb_define_class("Instruction", rb_cObject));
	instr_type_klass = rb_define_module_under(instr_klass, "Type");
	
	rb_define_const(instr_type_klass, "ASC", INT2FIX(INSTRUCTION_TYPE_ASC));
	rb_define_const(instr_type_klass, "DCL", INT2FIX(INSTRUCTION_TYPE_DCL));
	rb_define_const(instr_type_klass, "MOV", INT2FIX(INSTRUCTION_TYPE_MOV));
	rb_define_const(instr_type_klass, "MOVSR", INT2FIX(INSTRUCTION_TYPE_MOVSR));
	rb_define_const(instr_type_klass, "ADD", INT2FIX(INSTRUCTION_TYPE_ADD));
	rb_define_const(instr_type_klass, "XADD", INT2FIX(INSTRUCTION_TYPE_XADD));
	rb_define_const(instr_type_klass, "ADC", INT2FIX(INSTRUCTION_TYPE_ADC));
	rb_define_const(instr_type_klass, "SUB", INT2FIX(INSTRUCTION_TYPE_SUB));
	rb_define_const(instr_type_klass, "SBB", INT2FIX(INSTRUCTION_TYPE_SBB));
	rb_define_const(instr_type_klass, "INC", INT2FIX(INSTRUCTION_TYPE_INC));
	rb_define_const(instr_type_klass, "DEC", INT2FIX(INSTRUCTION_TYPE_DEC));
	rb_define_const(instr_type_klass, "DIV", INT2FIX(INSTRUCTION_TYPE_DIV));
	rb_define_const(instr_type_klass, "IDIV", INT2FIX(INSTRUCTION_TYPE_IDIV));
	rb_define_const(instr_type_klass, "NOT", INT2FIX(INSTRUCTION_TYPE_NOT));
	rb_define_const(instr_type_klass, "NEG", INT2FIX(INSTRUCTION_TYPE_NEG));
	rb_define_const(instr_type_klass, "STOS", INT2FIX(INSTRUCTION_TYPE_STOS));
	rb_define_const(instr_type_klass, "LODS", INT2FIX(INSTRUCTION_TYPE_LODS));
	rb_define_const(instr_type_klass, "SCAS", INT2FIX(INSTRUCTION_TYPE_SCAS));
	rb_define_const(instr_type_klass, "MOVS", INT2FIX(INSTRUCTION_TYPE_MOVS));
	rb_define_const(instr_type_klass, "MOVSX", INT2FIX(INSTRUCTION_TYPE_MOVSX));
	rb_define_const(instr_type_klass, "MOVZX", INT2FIX(INSTRUCTION_TYPE_MOVZX));
	rb_define_const(instr_type_klass, "CMPS", INT2FIX(INSTRUCTION_TYPE_CMPS));
	rb_define_const(instr_type_klass, "SHX", INT2FIX(INSTRUCTION_TYPE_SHX));
	rb_define_const(instr_type_klass, "ROX", INT2FIX(INSTRUCTION_TYPE_ROX));
	rb_define_const(instr_type_klass, "MUL", INT2FIX(INSTRUCTION_TYPE_MUL));
	rb_define_const(instr_type_klass, "IMUL", INT2FIX(INSTRUCTION_TYPE_IMUL));
	rb_define_const(instr_type_klass, "EIMUL", INT2FIX(INSTRUCTION_TYPE_EIMUL));
	rb_define_const(instr_type_klass, "XOR", INT2FIX(INSTRUCTION_TYPE_XOR));
	rb_define_const(instr_type_klass, "LEA", INT2FIX(INSTRUCTION_TYPE_LEA));
	rb_define_const(instr_type_klass, "XCHG", INT2FIX(INSTRUCTION_TYPE_XCHG));
	rb_define_const(instr_type_klass, "CMP", INT2FIX(INSTRUCTION_TYPE_CMP));
	rb_define_const(instr_type_klass, "TEST", INT2FIX(INSTRUCTION_TYPE_TEST));
	rb_define_const(instr_type_klass, "PUSH", INT2FIX(INSTRUCTION_TYPE_PUSH));
	rb_define_const(instr_type_klass, "AND", INT2FIX(INSTRUCTION_TYPE_AND));
	rb_define_const(instr_type_klass, "OR", INT2FIX(INSTRUCTION_TYPE_OR));
	rb_define_const(instr_type_klass, "POP", INT2FIX(INSTRUCTION_TYPE_POP));
	rb_define_const(instr_type_klass, "JMP", INT2FIX(INSTRUCTION_TYPE_JMP));
	rb_define_const(instr_type_klass, "JMPC", INT2FIX(INSTRUCTION_TYPE_JMPC));
	rb_define_const(instr_type_klass, "SETC", INT2FIX(INSTRUCTION_TYPE_SETC));
	rb_define_const(instr_type_klass, "MOVC", INT2FIX(INSTRUCTION_TYPE_MOVC));
	rb_define_const(instr_type_klass, "LOOP", INT2FIX(INSTRUCTION_TYPE_LOOP));
	rb_define_const(instr_type_klass, "CALL", INT2FIX(INSTRUCTION_TYPE_CALL));
	rb_define_const(instr_type_klass, "RET", INT2FIX(INSTRUCTION_TYPE_RET));
	rb_define_const(instr_type_klass, "INT", INT2FIX(INSTRUCTION_TYPE_INT));
	rb_define_const(instr_type_klass, "BT", INT2FIX(INSTRUCTION_TYPE_BT));
	rb_define_const(instr_type_klass, "BTS", INT2FIX(INSTRUCTION_TYPE_BTS));
	rb_define_const(instr_type_klass, "BTR", INT2FIX(INSTRUCTION_TYPE_BTR));
	rb_define_const(instr_type_klass, "BTC", INT2FIX(INSTRUCTION_TYPE_BTC));
	rb_define_const(instr_type_klass, "BSF", INT2FIX(INSTRUCTION_TYPE_BSF));
	rb_define_const(instr_type_klass, "BSR", INT2FIX(INSTRUCTION_TYPE_BSR));
	rb_define_const(instr_type_klass, "BSWAP", INT2FIX(INSTRUCTION_TYPE_BSWAP));
	rb_define_const(instr_type_klass, "SGDT", INT2FIX(INSTRUCTION_TYPE_SGDT));
	rb_define_const(instr_type_klass, "SIDT", INT2FIX(INSTRUCTION_TYPE_SIDT));
	rb_define_const(instr_type_klass, "SLDT", INT2FIX(INSTRUCTION_TYPE_SLDT));
	rb_define_const(instr_type_klass, "LFP", INT2FIX(INSTRUCTION_TYPE_LFP));
	rb_define_const(instr_type_klass, "FCMOVC", INT2FIX(INSTRUCTION_TYPE_FCMOVC));
	rb_define_const(instr_type_klass, "FADD", INT2FIX(INSTRUCTION_TYPE_FADD));
	rb_define_const(instr_type_klass, "FADDP", INT2FIX(INSTRUCTION_TYPE_FADDP));
	rb_define_const(instr_type_klass, "FIADD", INT2FIX(INSTRUCTION_TYPE_FIADD));
	rb_define_const(instr_type_klass, "FSUB", INT2FIX(INSTRUCTION_TYPE_FSUB));
	rb_define_const(instr_type_klass, "FSUBP", INT2FIX(INSTRUCTION_TYPE_FSUBP));
	rb_define_const(instr_type_klass, "FISUB", INT2FIX(INSTRUCTION_TYPE_FISUB));
	rb_define_const(instr_type_klass, "FSUBR", INT2FIX(INSTRUCTION_TYPE_FSUBR));
	rb_define_const(instr_type_klass, "FSUBRP", INT2FIX(INSTRUCTION_TYPE_FSUBRP));
	rb_define_const(instr_type_klass, "FISUBR", INT2FIX(INSTRUCTION_TYPE_FISUBR));
	rb_define_const(instr_type_klass, "FMUL", INT2FIX(INSTRUCTION_TYPE_FMUL));
	rb_define_const(instr_type_klass, "FMULP", INT2FIX(INSTRUCTION_TYPE_FMULP));
	rb_define_const(instr_type_klass, "FIMUL", INT2FIX(INSTRUCTION_TYPE_FIMUL));
	rb_define_const(instr_type_klass, "FDIV", INT2FIX(INSTRUCTION_TYPE_FDIV));
	rb_define_const(instr_type_klass, "FDIVP", INT2FIX(INSTRUCTION_TYPE_FDIVP));
	rb_define_const(instr_type_klass, "FDIVR", INT2FIX(INSTRUCTION_TYPE_FDIVR));
	rb_define_const(instr_type_klass, "FDIVRP", INT2FIX(INSTRUCTION_TYPE_FDIVRP));
	rb_define_const(instr_type_klass, "FIDIV", INT2FIX(INSTRUCTION_TYPE_FIDIV));
	rb_define_const(instr_type_klass, "FIDIVR", INT2FIX(INSTRUCTION_TYPE_FIDIVR));
	rb_define_const(instr_type_klass, "FCOM", INT2FIX(INSTRUCTION_TYPE_FCOM));
	rb_define_const(instr_type_klass, "FCOMP", INT2FIX(INSTRUCTION_TYPE_FCOMP));
	rb_define_const(instr_type_klass, "FCOMPP", INT2FIX(INSTRUCTION_TYPE_FCOMPP));
	rb_define_const(instr_type_klass, "FCOMI", INT2FIX(INSTRUCTION_TYPE_FCOMI));
	rb_define_const(instr_type_klass, "FCOMIP", INT2FIX(INSTRUCTION_TYPE_FCOMIP));
	rb_define_const(instr_type_klass, "FUCOM", INT2FIX(INSTRUCTION_TYPE_FUCOM));
	rb_define_const(instr_type_klass, "FUCOMP", INT2FIX(INSTRUCTION_TYPE_FUCOMP));
	rb_define_const(instr_type_klass, "FUCOMPP", INT2FIX(INSTRUCTION_TYPE_FUCOMPP));
	rb_define_const(instr_type_klass, "FUCOMI", INT2FIX(INSTRUCTION_TYPE_FUCOMI));
	rb_define_const(instr_type_klass, "FUCOMIP", INT2FIX(INSTRUCTION_TYPE_FUCOMIP));
	rb_define_const(instr_type_klass, "FST", INT2FIX(INSTRUCTION_TYPE_FST));
	rb_define_const(instr_type_klass, "FSTP", INT2FIX(INSTRUCTION_TYPE_FSTP));
	rb_define_const(instr_type_klass, "FIST", INT2FIX(INSTRUCTION_TYPE_FIST));
	rb_define_const(instr_type_klass, "FISTP", INT2FIX(INSTRUCTION_TYPE_FISTP));
	rb_define_const(instr_type_klass, "FISTTP", INT2FIX(INSTRUCTION_TYPE_FISTTP));
	rb_define_const(instr_type_klass, "FLD", INT2FIX(INSTRUCTION_TYPE_FLD));
	rb_define_const(instr_type_klass, "FILD", INT2FIX(INSTRUCTION_TYPE_FILD));
	rb_define_const(instr_type_klass, "FICOM", INT2FIX(INSTRUCTION_TYPE_FICOM));
	rb_define_const(instr_type_klass, "FICOMP", INT2FIX(INSTRUCTION_TYPE_FICOMP));
	rb_define_const(instr_type_klass, "FFREE", INT2FIX(INSTRUCTION_TYPE_FFREE));
	rb_define_const(instr_type_klass, "FFREEP", INT2FIX(INSTRUCTION_TYPE_FFREEP));
	rb_define_const(instr_type_klass, "FXCH", INT2FIX(INSTRUCTION_TYPE_FXCH));
	rb_define_const(instr_type_klass, "FPU", INT2FIX(INSTRUCTION_TYPE_FPU));
	rb_define_const(instr_type_klass, "MMX", INT2FIX(INSTRUCTION_TYPE_MMX));
	rb_define_const(instr_type_klass, "SSE", INT2FIX(INSTRUCTION_TYPE_SSE));
	rb_define_const(instr_type_klass, "OTHER", INT2FIX(INSTRUCTION_TYPE_OTHER));
	rb_define_const(instr_type_klass, "PRIV", INT2FIX(INSTRUCTION_TYPE_PRIV));

	rb_define_alloc_func(instr_klass, instruction_alloc);
	rb_define_method(instr_klass, "length", instruction_length, 0);
	rb_define_method(instr_klass, "type", instruction_type, 0);
	rb_define_method(instr_klass, "mode", instruction_mode, 0);
	rb_define_method(instr_klass, "opcode", instruction_opcode, 0);
	rb_define_method(instr_klass, "modrm", instruction_modrm, 0);
	rb_define_method(instr_klass, "sib", instruction_sib, 0);
	rb_define_method(instr_klass, "dispbytes", instruction_dispbytes, 0);
	rb_define_method(instr_klass, "immbytes", instruction_immbytes, 0);
	rb_define_method(instr_klass, "sectionbytes", instruction_sectionbytes, 0);
	rb_define_method(instr_klass, "flags", instruction_flags, 0);
	rb_define_method(instr_klass, "raw", instruction_raw, 0);
	rb_define_method(instr_klass, "to_s", instruction_to_s, 0);
	rb_define_method(instr_klass, "op1", instruction_op1, 0);
	rb_define_method(instr_klass, "op2", instruction_op2, 0);
	rb_define_method(instr_klass, "op3", instruction_op3, 0);
	rb_define_method(instr_klass, "eflags_affected", instruction_eflags_affected, 0);
	rb_define_method(instr_klass, "eflags_used", instruction_eflags_used, 0);

	// Operand
	oper_klass = rb_define_class_under(dasm_klass, "Operand",
		rb_define_class("Operand", rb_cObject));
	oper_type_klass = rb_define_module_under(oper_klass, "Type");

	rb_define_alloc_func(oper_klass, operand_alloc);
	rb_define_method(oper_klass, "type", operand_type, 0);
	rb_define_method(oper_klass, "reg", operand_reg, 0);
	rb_define_method(oper_klass, "regtype", operand_regtype, 0);
	rb_define_method(oper_klass, "basereg", operand_basereg, 0);
	rb_define_method(oper_klass, "indexreg", operand_indexreg, 0);
	rb_define_method(oper_klass, "scale", operand_scale, 0);
	rb_define_method(oper_klass, "dispbytes", operand_dispbytes, 0);
	rb_define_method(oper_klass, "dispoffset", operand_dispoffset, 0);
	rb_define_method(oper_klass, "immbytes", operand_immbytes, 0);
	rb_define_method(oper_klass, "immoffset", operand_immoffset, 0);
	rb_define_method(oper_klass, "sectionbytes", operand_sectionbytes, 0);
	rb_define_method(oper_klass, "section", operand_section, 0);
	rb_define_method(oper_klass, "displacement", operand_displacement, 0);
	rb_define_method(oper_klass, "immediate", operand_immediate, 0);
	rb_define_method(oper_klass, "flags", operand_flags, 0);
}
