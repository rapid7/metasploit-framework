// Copyright (C) 2004, Matt Conover (mconover@gmail.com)
#undef NDEBUG
#include <assert.h>
#include "disasm.h"
#include "cpu.h"

// Since addresses are internally represented as 64-bit, we need to specially handle
// cases where IP + Displacement wraps around for 16-bit/32-bit operand size
// Otherwise, ignorethe possibility of wraparounds
#define SUPPORT_WRAPAROUND

#ifdef NO_SANITY_CHECKS
#undef NDEBUG
#undef DEBUG_DISASM
#undef assert
#define assert(x)
#endif

#ifdef DEBUG_DISASM
#define DISASM_OUTPUT(x) printf x
#else
#define DISASM_OUTPUT(x)
#endif

#include "disasm_x86_tables.h"

#ifdef _WIN64
#pragma warning(disable:4311 4312)
#endif

////////////////////////////////////////////////////////////////////////
// Internal macros
////////////////////////////////////////////////////////////////////////

#define VIRTUAL_ADDRESS ((U64)Instruction->Address + Instruction->VirtualAddressDelta)

#define AMD64_DIFF (AMD64_8BIT_OFFSET-X86_8BIT_OFFSET)
#define IS_AMD64() (INS_ARCH_TYPE(Instruction) == ARCH_X64)
#define IS_X86_32() (INS_ARCH_TYPE(Instruction) == ARCH_X86)
#define IS_X86_16() (INS_ARCH_TYPE(Instruction) == ARCH_X86_16)

#define X86_BOUND 0x62
#define X86_PUSH_REG 0x50
#define X86_PUSH_CS 0x0e
#define X86_PUSH_DS 0x1e
#define X86_PUSH_SS 0x16
#define X86_PUSH_ES 0x06
#define X86_PUSH_FS 0xa0
#define X86_PUSH_GS 0xa8
#define X86_PUSH_U8 0x6a
#define X86_PUSH_U32 0x68
#define X86_POP_DS 0x1f
#define X86_POP_ES 0x07
#define X86_POP_SS 0x17
#define X86_POP_FS 0xa1
#define X86_POP_GS 0xa9
#define X86_POP_REG 0x58

#define OPCSTR Instruction->String+Instruction->StringIndex
#define APPEND Instruction->StringIndex += (U8)_snprintf
#define APPENDPAD(x) \
{ \
	if (Instruction->StringAligned) \
	{  \
			if (Instruction->StringIndex > x) assert(0); \
			while (x != Instruction->StringIndex) APPENDB(' ');  \
	}  \
	else if (Instruction->StringIndex) \
	{  \
		APPENDB(' '); \
	} \
}

#define APPENDB(a) Instruction->String[Instruction->StringIndex++] = a
#define APPENDS(a) APPEND(OPCSTR, SIZE_LEFT, a);

#define SIZE_LEFT (MAX_OPCODE_DESCRIPTION-1 > Instruction->StringIndex ? MAX_OPCODE_DESCRIPTION-Instruction->StringIndex : 0)

// If an address size prefix is used for an instruction that doesn't make sense, restore it
// to the default

#define SANITY_CHECK_OPERAND_SIZE() \
{ \
	if (!Instruction->AnomalyOccurred && X86Instruction->HasOperandSizePrefix) \
	{ \
		if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Unexpected operand size prefix\n", VIRTUAL_ADDRESS); \
		Instruction->AnomalyOccurred = TRUE; \
		X86Instruction->HasOperandSizePrefix = FALSE; \
		switch (X86Instruction->OperandSize) \
		{ \
			case 4: X86Instruction->OperandSize = 2; break; \
			case 2: X86Instruction->OperandSize = 4; break; \
			default: assert(0); \
		} \
	} \
}

#define SANITY_CHECK_ADDRESS_SIZE() \
{ \
	if (!Instruction->AnomalyOccurred && X86Instruction->HasAddressSizePrefix) \
	{ \
		if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Unexpected address size prefix\n", VIRTUAL_ADDRESS); \
		Instruction->AnomalyOccurred = TRUE; \
	} \
	X86Instruction->HasAddressSizePrefix = FALSE; \
	switch (INS_ARCH_TYPE(Instruction)) \
	{ \
		case ARCH_X64: X86Instruction->AddressSize = 8; break; \
		case ARCH_X86: X86Instruction->AddressSize = 4; break; \
		case ARCH_X86_16: X86Instruction->AddressSize = 2; break; \
	} \
}

#define SANITY_CHECK_SEGMENT_OVERRIDE() \
	if (!Instruction->AnomalyOccurred && X86Instruction->HasSegmentOverridePrefix) \
	{ \
		if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Unexpected segment override\n", VIRTUAL_ADDRESS); \
		Instruction->AnomalyOccurred = TRUE; \
	}

#define INSTR_INC(size) \
{ \
	Instruction->Length += size; \
	Address += size; \
}

#define X86_SET_TARGET() \
{ \
	if (X86Instruction->HasSelector) \
	{ \
		if (!Instruction->AnomalyOccurred) \
		{ \
			if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: unexpected segment 0x%02X\n", VIRTUAL_ADDRESS, X86Instruction->Selector); \
			Instruction->AnomalyOccurred = TRUE; \
		} \
	} \
	else \
	{ \
		switch (X86Instruction->Segment) \
		{ \
			case SEG_CS: \
			case SEG_DS: \
			case SEG_SS: \
			case SEG_ES: \
				assert(!X86Instruction->HasSelector); \
				Operand->TargetAddress = (U64)X86Instruction->Displacement; \
				/* assert(!GetAbsoluteAddressFromSegment((BYTE)X86Instruction->Segment, (DWORD)X86Instruction->Displacement) || GetAbsoluteAddressFromSegment(X86Instruction->Segment, (DWORD)X86Instruction->Displacement) == Operand->TargetAddress); */ \
				break; \
			case SEG_FS: \
			case SEG_GS: \
				assert(!X86Instruction->HasSelector); \
				Operand->TargetAddress = (U64)GetAbsoluteAddressFromSegment((BYTE)X86Instruction->Segment, (DWORD)X86Instruction->Displacement); \
				break; \
			default: \
				assert(0); /* shouldn't be possible */ \
				break; \
		} \
	} \
}

#define X86_SET_SEG(reg) \
{ \
	if (!X86Instruction->HasSegmentOverridePrefix && (reg == REG_EBP || reg == REG_ESP)) \
	{ \
		assert(!X86Instruction->HasSelector); \
		X86Instruction->Segment = SEG_SS; \
	} \
}

#define X86_SET_ADDR() \
{ \
	if (Operand->Flags & OP_DST) \
	{ \
		assert(!X86Instruction->HasDstAddressing); \
		X86Instruction->HasDstAddressing = TRUE; \
		X86Instruction->DstOpIndex[X86Instruction->DstOpCount] = (U8)OperandIndex; \
		X86Instruction->DstOpCount++; \
		X86Instruction->DstAddressIndex = (U8)OperandIndex; \
	} \
	if (Operand->Flags & OP_SRC) \
	{ \
		if (Instruction->Type != ITYPE_STRCMP) assert(!X86Instruction->HasSrcAddressing); \
		X86Instruction->HasSrcAddressing = TRUE; \
		X86Instruction->SrcOpIndex[X86Instruction->SrcOpCount] = (U8)OperandIndex; \
		X86Instruction->SrcOpCount++; \
		X86Instruction->SrcAddressIndex = (U8)OperandIndex; \
	} \
}

#define X86_SET_REG(reg) \
{ \
	if (Operand->Flags & OP_DST) \
	{ \
		X86Instruction->DstOpIndex[X86Instruction->DstOpCount] = (U8)OperandIndex; \
		X86Instruction->DstOpCount++; \
		assert(OperandIndex < 2); \
		if (Operand->Length > 1 && reg == REG_ESP) Instruction->Groups |= ITYPE_STACK; \
	} \
	if (Operand->Flags & OP_SRC) \
	{ \
		X86Instruction->SrcOpIndex[X86Instruction->SrcOpCount] = (U8)OperandIndex; \
		X86Instruction->SrcOpCount++; \
	} \
} 

#define CHECK_AMD64_REG() { if (IS_AMD64()) Operand->Register += AMD64_DIFF; }

////////////////////////////////////////////////////////////////////////
// Internal structures/variables
////////////////////////////////////////////////////////////////////////

ARCHITECTURE_FORMAT_FUNCTIONS X86 = 
{
	X86_InitInstruction, 
	NULL,
	X86_GetInstruction,
	X86_FindFunctionByPrologue 
};

char *X86_Registers[0xE0] = 
{
	// Segments
	"es", // 0x00
	"cs", // 0x01
	"ss", // 0x02
	"ds", // 0x03
	"fs", // 0x04
	"gs", // 0x05
	"flags", // 0x06
	"eflags", // 0x07
	"rflags", // 0x08
	"ip+ilen", // 0x09
	"eip+ilen", // 0x0A
	"rip+ilen", // 0x0B
	NULL, // 0x0C
	NULL, // 0x0D
	NULL, // 0x0E
	NULL, // 0x0F

	// Test
	"tr0", // 0x10
	"tr1", // 0x11
	"tr2", // 0x12
	"tr3", // 0x13
	"tr4", // 0x14
	"tr5", // 0x15
	"tr6", // 0x16
	"tr7", // 0x17
	"tr8", // 0x18
	"tr9", // 0x19
	"tr10", // 0x1A
	"tr11", // 0x1B
	"tr12", // 0x1C
	"tr13", // 0x1D
	"tr14", // 0x1E
	"tr15", // 0x1F

	// Control
	"cr0", // 0x20
	"cr1", // 0x21
	"cr2", // 0x22
	"cr3", // 0x23
	"cr4", // 0x24
	"cr5", // 0x25
	"cr6", // 0x26
	"cr7", // 0x27
	"cr8", // 0x18
	"cr9", // 0x19
	"cr10", // 0x1A
	"cr11", // 0x1B
	"cr12", // 0x1C
	"cr13", // 0x1D
	"cr14", // 0x1E
	"cr15", // 0x1F

	// Debug
	"dr0", // 0x30
	"dr1", // 0x31
	"dr2", // 0x32
	"dr3", // 0x33
	"dr4", // 0x34
	"dr5", // 0x35
	"dr6", // 0x36
	"dr7", // 0x37
	"dr8", // 0x38
	"dr9", // 0x39
	"dr10", // 0x3A
	"dr11", // 0x3B
	"dr12", // 0x3C
	"dr13", // 0x3D
	"dr14", // 0x3E
	"dr15", // 0x3F

	// FPU
	"st(0)", // 0x40
	"st(1)", // 0x41
	"st(2)", // 0x42
	"st(3)", // 0x43
	"st(4)", // 0x44
	"st(5)", // 0x45
	"st(6)", // 0x46
	"st(7)", // 0x47
	NULL, // 0x48
	NULL, // 0x49
	NULL, // 0x4A
	NULL, // 0x4B
	NULL, // 0x4C
	NULL, // 0x4D
	NULL, // 0x4E
	NULL, // 0x4F

	// MMX
	"mm0", // 0x50
	"mm1", // 
	"mm2",
	"mm3",
	"mm4",
	"mm5",
	"mm6",
	"mm7",
	NULL, // 0x58
	NULL, // 0x59
	NULL, // 0x5A
	NULL, // 0x5B
	NULL, // 0x5C
	NULL, // 0x5D
	NULL, // 0x5E
	NULL, // 0x5F

	// XMM
	"xmm0", // 0x60
	"xmm1", // 0x61
	"xmm2", // 0x62
	"xmm3", // 0x63
	"xmm4", // 0x64
	"xmm5", // 0x65
	"xmm6", // 0x66
	"xmm7", // 0x67
	"xmm8", // 0x68
	"xmm9", // 0x69
	"xmm10", // 0x6a
	"xmm11", // 0x6b
	"xmm12", // 0x6c
	"xmm13", // 0x6d
	"xmm14", // 0x6e
	"xmm15", // 0x6f

	// 8-bit
	"al", // 0x70
	"cl", // 0x71
	"dl", // 0x72
	"bl", // 0x73
	"ah", // 0x74
	"ch", // 0x75
	"dh", // 0x76
	"bh", // 0x77
 	NULL, // 0x78
	NULL, // 0x79
	NULL, // 0x7A
	NULL, // 0x7B
	NULL, // 0x7C
	NULL, // 0x7D
	NULL, // 0x7E
	NULL, // 0x7F

	// 16-bit
	"ax", // 0x80
	"cx", // 0x81
	"dx", // 0x82
	"bx", // 0x83
	"sp", // 0x84
	"bp", // 0x85
	"si", // 0x86
	"di", // 0x87
	NULL, // 0x88
	NULL, // 0x89
	NULL, // 0x8A
	NULL, // 0x8B
	NULL, // 0x8C
	NULL, // 0x8D
	NULL, // 0x8E
	NULL, // 0x8F

	// 32-bit
	"eax", // 0x90
	"ecx", // 0x91
	"edx", // 0x92
	"ebx", // 0x93
	"esp", // 0x94
	"ebp", // 0x95
	"esi", // 0x96
	"edi", // 0x97
	NULL, // 0x98
	NULL, // 0x99
	NULL, // 0x9A
	NULL, // 0x9B
	NULL, // 0x9C
	NULL, // 0x9D
	NULL, // 0x9E
	NULL, // 0x9F

	// X86-64 8-bit register
	"al", // 0xA0
	"cl", // 0xA1
	"dl", // 0xA2
	"bl", // 0xA3
	"spl", // 0xA4
	"bpl", // 0xA5
	"sil", // 0xA6
	"dil", // 0xA7
	"r8b", // 0xA8
	"r9b", // 0xA9
	"r10b", // 0xAA
	"r11b", // 0xAB
	"r12b", // 0xAC
	"r13b", // 0xAD
	"r14b", // 0xAE
	"r15b", // 0xAF

	// X86-64 16-bit register	
	"ax", // 0xB0
	"cx", // 0xB1
	"dx", // 0xB2
	"bx", // 0xB3
	"sp", // 0xB4
	"bp", // 0xB5
	"si", // 0xB6
	"di", // 0xB7
	"r8w", // 0xB8
	"r9w", // 0xB9
	"r10w", // 0xBA
	"r11w", // 0xBB
	"r12w", // 0xBC
	"r13w", // 0xBD
	"r14w", // 0xBE
	"r15w", // 0xBF

	// X86-64 32-bit register
	"eax", // 0xC0
	"ecx", // 0xC1
	"edx", // 0xC2
	"ebx", // 0xC3
	"esp", // 0xC4
	"ebp", // 0xC5
	"esi", // 0xC6
	"edi", // 0xC7
	"r8d", // 0xC8
	"r9d", // 0xC9
	"r10d", // 0xCA
	"r11d", // 0xCB
	"r12d", // 0xCC
	"r13d", // 0xCD
	"r14d", // 0xCE
	"r15d", // 0xCF

	// X86-64 64-bit register	
	"rax", // 0xD0
	"rcx", // 0xD1
	"rdx", // 0xD2
	"rbx", // 0xD3
	"rsp", // 0xD4
	"rbp", // 0xD5
	"rsi", // 0xD6
	"rdi", // 0xD7
	"r8", // 0xD8
	"r9", // 0xD9
	"r10", // 0xDA
	"r11", // 0xDB
	"r12", // 0xDC
	"r13", // 0xDD
	"r14", // 0xDE
	"r15" // 0xDF
};

void OutputBounds(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputGeneral(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputDescriptor(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputSegOffset(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputPackedReal(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputPackedBCD(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputScalarReal(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputScalarGeneral(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputFPUEnvironment(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputFPUState(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
void OutputCPUState(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);

typedef void (*OUTPUT_OPTYPE)(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex);
#define OPTYPE_SHIFT 24
#define MAX_OPTYPE_INDEX 26
OUTPUT_OPTYPE OptypeHandlers[] =
{
	NULL,
	OutputBounds,         // 01 OPTYPE_a
	OutputGeneral,        // 02 OPTYPE_b
	OutputGeneral,        // 03 OPTYPE_d
	OutputSegOffset,      // 04 OPTYPE_p
	OutputGeneral,        // 05 OPTYPE_q
	OutputDescriptor,     // 06 OPTYPE_dt
	OutputGeneral,        // 07 OPTYPE_v
	OutputGeneral,        // 08 OPTYPE_w
	OutputPackedReal,     // 09 OPTYPE_ps
	OutputPackedReal,     // 0A OPTYPE_pd
	OutputPackedBCD,      // 0B OPTYPE_pb
	OutputScalarReal,     // 0C OPTYPE_ss
	OutputScalarReal,     // 0D OPTYPE_sd
	OutputScalarReal,     // 0E OPTYPE_se
	OutputFPUEnvironment, // 0F OPTYPE_fev
	OutputFPUState,       // 10 OPTYPE_fst1
	OutputFPUState,       // 11 OPTYPE_fst2
	OutputGeneral,        // 12 OPTYPE_z
	OutputGeneral,        // 13 OPTYPE_o
	OutputGeneral,        // 14 OPTYPE_dq
	OutputGeneral,        // 15 OPTYPE_mw
	OutputScalarGeneral,  // 16 OPTYPE_sso
	OutputScalarGeneral,  // 17 OPTYPE_sdo
	OutputCPUState,       // 18 OPTYPE_cpu
	OutputGeneral,        // 19 OPTYPE_lea
};

#define OPTYPE_a    0x01000000
#define OPTYPE_b    0x02000000
#define OPTYPE_d    0x03000000
#define OPTYPE_p    0x04000000
#define OPTYPE_q    0x05000000
#define OPTYPE_dt   0x06000000
#define OPTYPE_v    0x07000000
#define OPTYPE_w    0x08000000
#define OPTYPE_ps   0x09000000 // packed 128-bit single real
#define OPTYPE_pd   0x0A000000 // packed 128-bit double real
#define OPTYPE_pb	  0x0B000000 // packed BCD (10 bytes, 18-bit precision)
#define OPTYPE_ss   0x0C000000 // scalar single real
#define OPTYPE_sd   0x0D000000 // scalar double real
#define OPTYPE_se   0x0E000000 // scalar extended real
#define OPTYPE_fev  0x0F000000 // FPU environment (28 bytes if 32-bit modes, 14 bytes in 16-bit mode)
#define OPTYPE_fst1 0x10000000 // FPU state (108 bytes in 32-bit modes, 94 bytes in 16-bit real mode)
#define OPTYPE_fst2 0x11000000 // FPU/MMX/XMM/MXCSR state (512 bytes)
#define OPTYPE_z	  0x12000000
#define OPTYPE_o	  0x13000000
#define OPTYPE_dq   0x14000000 // OPTYPE_d or OPTYPE_o
#define OPTYPE_mw   0x15000000 // word if memory, register size otherwise
#define OPTYPE_sso  0x16000000 // OPTYPE_ss or OPTYPE_o
#define OPTYPE_sdo  0x17000000 // OPTYPE_ss or OPTYPE_o
#define OPTYPE_cpu  0x18000000 // pointer to CPU state structure
#define OPTYPE_lea  0x19000000 // size set by other operand

////////////////////////////////////////////////////////////////////////
// Internal functions
////////////////////////////////////////////////////////////////////////

#ifdef TEST_DISASM // TODO: remove
U32 X86_GetLength(INSTRUCTION *Instruction, U8 *Address);
#endif

INTERNAL BOOL IsValidLockPrefix(X86_INSTRUCTION *Instruction, U8 Opcode, U32 OpcodeLength, U8 Group, U8 OpcodeExtension);
INTERNAL U8 *SetOperands(INSTRUCTION *Instruction, U8 *Address, U32 Flags);
INTERNAL U8 *SetModRM32(INSTRUCTION *Instruction, U8 *Address, INSTRUCTION_OPERAND *Operand, U32 OperandIndex, BOOL SuppressErrors);
INTERNAL U8 *SetModRM16(INSTRUCTION *Instruction, U8 *Address, INSTRUCTION_OPERAND *Operand, U32 OperandIndex, BOOL SuppressErrors);
INTERNAL U8 *SetSIB(INSTRUCTION *Instruction, U8 *Address, INSTRUCTION_OPERAND *Operand, U32 OperandIndex, BOOL SuppressErrors);
INTERNAL U64 ApplyDisplacement(U64 Address, INSTRUCTION *Instruction);

//////////////////////////////////////////////////////////
// Instruction setup
//////////////////////////////////////////////////////////

#define APPLY_OFFSET(addr) \
{ \
	switch (X86Instruction->OperandSize) \
	{ \
		case 8: addr = ((U64)(addr + Instruction->VirtualAddressDelta)); break; \
		case 4: addr = (U64)((U32)(addr + Instruction->VirtualAddressDelta)); break; \
		case 2: addr = (U64)((U8)(addr + Instruction->VirtualAddressDelta)); break; \
		default: assert(0); break; \
	} \
}

BOOL X86_InitInstruction(INSTRUCTION *Instruction)
{
	X86_INSTRUCTION *X86Instruction;
#ifdef NO_SANITY_CHECKS
	assert(0); // be sure assertions are disabled
#endif
	X86Instruction = &Instruction->X86;
	memset(X86Instruction, 0, sizeof(X86_INSTRUCTION));
	
	switch (INS_ARCH_TYPE(Instruction))
	{
		case ARCH_X64:
			X86Instruction->AddressSize = 8;
			X86Instruction->OperandSize = 4;
			break;
		case ARCH_X86:
			X86Instruction->AddressSize = 4;
			X86Instruction->OperandSize = 4;
			break;
		case ARCH_X86_16:
			X86Instruction->AddressSize = 2;
			X86Instruction->OperandSize = 2;
			break;
		default:
			assert(0);
			return FALSE;
	}
	X86Instruction->Instruction = Instruction;
	X86Instruction->Segment = SEG_DS;
	return TRUE;
}

////////////////////////////////////////////////////////////
// Formatting
// You can change these to whatever you prefer
////////////////////////////////////////////////////////////

#define X86_WRITE_OPFLAGS() \
	if (Flags & DISASM_SHOWFLAGS) \
	{ \
		APPENDB('{'); \
		assert(Operand->Flags & (OP_EXEC|OP_SRC|OP_DST)); \
		if (Operand->Flags & OP_IPREL) APPENDB('r'); \
		if (Operand->Flags & OP_FAR) APPENDB('f'); \
		if (Operand->Flags & OP_CONDR) APPENDB('c'); \
		if (Operand->Flags & OP_EXEC) APPENDB('X'); \
		else if (Operand->Flags & OP_SRC) APPENDB('R'); \
		if (Operand->Flags & OP_CONDW) APPENDB('c'); \
		if (Operand->Flags & OP_DST) APPENDB('W'); \
		if (Operand->Flags & OP_SYS) APPENDB('S'); \
		if (Operand->Flags & OP_ADDRESS) APPENDB('A'); \
		if (Operand->Flags & OP_PARAM) APPENDB('P'); \
		if (Operand->Flags & OP_LOCAL) APPENDB('L'); \
		if (Operand->Flags & OP_GLOBAL) APPENDB('G'); \
		APPENDB('}'); \
	}

#define X86_WRITE_IMMEDIATE() \
{ \
	switch (Operand->Length) \
	{ \
		case 8: \
			APPEND(OPCSTR, SIZE_LEFT, "0x%02I64X=", Operand->Value_U64); \
			if (Operand->Value_S64 >= 0 || !(Operand->Flags & OP_SIGNED)) APPEND(OPCSTR, SIZE_LEFT, "%I64u", Operand->Value_U64); \
			/*else APPEND(OPCSTR, SIZE_LEFT, "-0x%02I64X=%I64d", -Operand->Value_S64, Operand->Value_S64);*/ \
			else APPEND(OPCSTR, SIZE_LEFT, "%I64d", Operand->Value_S64); \
			break; \
		case 4: \
			APPEND(OPCSTR, SIZE_LEFT, "0x%02lX=", (U32)Operand->Value_U64); \
			if (Operand->Value_S64 >= 0 || !(Operand->Flags & OP_SIGNED)) APPEND(OPCSTR, SIZE_LEFT, "%lu", (U32)Operand->Value_U64); \
			/*else APPEND(OPCSTR, SIZE_LEFT, "-0x%02lX=%ld", (U32)-Operand->Value_S64, (S32)Operand->Value_S64);*/ \
			else APPEND(OPCSTR, SIZE_LEFT, "%ld", (S32)Operand->Value_S64); \
			break; \
		case 2: \
			APPEND(OPCSTR, SIZE_LEFT, "0x%02X=", (U16)Operand->Value_U64); \
			if (Operand->Value_S64 >= 0 || !(Operand->Flags & OP_SIGNED)) APPEND(OPCSTR, SIZE_LEFT, "%u", (U16)Operand->Value_U64); \
			/*else APPEND(OPCSTR, SIZE_LEFT, "-0x%02X=%d", (U16)-Operand->Value_S64, (S16)Operand->Value_S64);*/ \
			else APPEND(OPCSTR, SIZE_LEFT, "%d", (S16)Operand->Value_S64); \
			break; \
		case 1: \
			APPEND(OPCSTR, SIZE_LEFT, "0x%02X=", (U8)Operand->Value_U64); \
			if (Operand->Value_S64 >= 0 || !(Operand->Flags & OP_SIGNED)) APPEND(OPCSTR, SIZE_LEFT, "%u", (U8)Operand->Value_U64); \
			/*else APPEND(OPCSTR, SIZE_LEFT, "-0x%02X=%d", (U8)-Operand->Value_S64, (S8)Operand->Value_S64);*/ \
			else APPEND(OPCSTR, SIZE_LEFT, "%d", (S8)Operand->Value_S64); \
			break; \
		default: assert(0); break; \
	} \
}

#define X86_WRITE_ABSOLUTE_DISPLACEMENT() \
{  \
	switch (X86Instruction->AddressSize) \
	{ \
		case 8: \
			APPEND(OPCSTR, SIZE_LEFT, "0x%04I64X", X86Instruction->Displacement); \
			break; \
		case 4: \
			APPEND(OPCSTR, SIZE_LEFT, "0x%04lX", (U32)X86Instruction->Displacement); \
			break; \
		case 2: \
			APPEND(OPCSTR, SIZE_LEFT, "0x%04X", (U16)X86Instruction->Displacement); \
			break; \
		default: assert(0); break; \
	} \
}

#define X86_WRITE_RELATIVE_DISPLACEMENT64() \
	if (X86Instruction->Displacement >= 0) APPEND(OPCSTR, SIZE_LEFT, "+0x%02I64X", X86Instruction->Displacement); \
	else APPEND(OPCSTR, SIZE_LEFT, "-0x%02I64X", -X86Instruction->Displacement);

#define X86_WRITE_RELATIVE_DISPLACEMENT32() \
	if (X86Instruction->Displacement >= 0) APPEND(OPCSTR, SIZE_LEFT, "+0x%02lX", (U32)X86Instruction->Displacement); \
	else APPEND(OPCSTR, SIZE_LEFT, "-0x%02lX", (U32)-X86Instruction->Displacement);

#define X86_WRITE_RELATIVE_DISPLACEMENT16() \
	if (X86Instruction->Displacement >= 0) APPEND(OPCSTR, SIZE_LEFT, "+0x%02X", (U16)X86Instruction->Displacement); \
	else APPEND(OPCSTR, SIZE_LEFT, "-0x%02X", (U16)-X86Instruction->Displacement);

#define X86_WRITE_RELATIVE_DISPLACEMENT() \
{  \
	switch (X86Instruction->AddressSize) \
	{ \
		case 8: \
			X86_WRITE_RELATIVE_DISPLACEMENT64() \
			break; \
		case 4: \
			X86_WRITE_RELATIVE_DISPLACEMENT32() \
			break; \
		case 2: \
			X86_WRITE_RELATIVE_DISPLACEMENT16() \
			break; \
		default: assert(0); break; \
	} \
}

#define X86_WRITE_IP_OFFSET(op) \
{ \
	switch (X86Instruction->OperandSize) \
	{ \
		case 8: \
			APPENDS("[rip+ilen"); \
			assert((op)->TargetAddress); \
			X86_WRITE_RELATIVE_DISPLACEMENT64() \
			APPEND(OPCSTR, SIZE_LEFT, "]=0x%04I64X", (op)->TargetAddress+Instruction->VirtualAddressDelta); \
			break; \
		case 4: \
			APPENDS("[eip+ilen"); \
			assert((op)->TargetAddress); \
			X86_WRITE_RELATIVE_DISPLACEMENT32() \
			APPEND(OPCSTR, SIZE_LEFT, "]=0x%04lX", (U32)((op)->TargetAddress+Instruction->VirtualAddressDelta)); \
			break; \
		case 2: \
			APPENDS("[ip+ilen"); \
			X86_WRITE_RELATIVE_DISPLACEMENT16() \
			APPEND(OPCSTR, SIZE_LEFT, "]=0x%04X", (U16)((op)->TargetAddress+Instruction->VirtualAddressDelta)); \
			break; \
		default: assert(0); break; \
	} \
}

#define X86_WRITE_OFFSET(op) \
{ \
	assert((op)->Length <= 8); \
	if (X86Instruction->HasSelector) \
	{ \
		assert((op)->Flags & OP_FAR); \
		APPEND(OPCSTR, SIZE_LEFT, "%s 0x%02X:[", DataSizes[((op)->Length >> 1)], X86Instruction->Selector); \
	} \
	else \
	{ \
		assert(!((op)->Flags & OP_FAR)); \
		assert(X86Instruction->Segment < SEG_MAX) ; \
		APPEND(OPCSTR, SIZE_LEFT, "%s %s:[", DataSizes[((op)->Length >> 1)], Segments[X86Instruction->Segment]); \
	} \
	X86_WRITE_ABSOLUTE_DISPLACEMENT() \
	APPENDB(']'); \
}

void OutputAddress(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	BOOL ShowDisplacement = FALSE;
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;

	assert(!X86Instruction->HasSelector);
	assert(X86Instruction->SrcAddressIndex == OperandIndex || X86Instruction->DstAddressIndex == OperandIndex);
	if (Operand->Length > 16 || (Operand->Length > 1 && (Operand->Length & 1))) APPEND(OPCSTR, SIZE_LEFT, "%d_byte ptr ", Operand->Length);
	else APPEND(OPCSTR, SIZE_LEFT, "%s ", DataSizes[Operand->Length >> 1]);

	//
	// This attempts to display the address intelligently
	// If it has a positive 32-bit displacement, it is shown as seg:Displacement[base+index*scale]
	// If it is a negative displacement or 8-bit, it is shown as seg:[base+index*scale+displacement]
	//
	APPEND(OPCSTR, SIZE_LEFT, "%s:", Segments[X86Instruction->Segment]);
	if (X86Instruction->HasBaseRegister)
	{
		if (X86Instruction->Displacement)
		{
			if (X86Instruction->HasFullDisplacement) X86_WRITE_ABSOLUTE_DISPLACEMENT()
			else ShowDisplacement = TRUE;
		}
		APPEND(OPCSTR, SIZE_LEFT, "[%s", X86_Registers[X86Instruction->BaseRegister]);
		if (X86Instruction->HasIndexRegister)
		{
			APPEND(OPCSTR, SIZE_LEFT, "+%s", X86_Registers[X86Instruction->IndexRegister]);
			if (X86Instruction->Scale > 1) APPEND(OPCSTR, SIZE_LEFT, "*%d", X86Instruction->Scale);
		}
		if (ShowDisplacement) X86_WRITE_RELATIVE_DISPLACEMENT()
		APPENDB(']');
		if (X86Instruction->Relative)
		{
			U64 Address = Operand->TargetAddress;
			assert(Address);
			APPLY_OFFSET(Address)
			APPEND(OPCSTR, SIZE_LEFT, "=[0x%04I64X]", Address);
		}
	}
	else if (X86Instruction->HasIndexRegister)
	{
		if (X86Instruction->Displacement)
		{
			if (X86Instruction->HasFullDisplacement) X86_WRITE_ABSOLUTE_DISPLACEMENT()
			else ShowDisplacement = TRUE;
		}
		APPEND(OPCSTR, SIZE_LEFT, "[%s", X86_Registers[X86Instruction->IndexRegister]);
		if (X86Instruction->Scale > 1) APPEND(OPCSTR, SIZE_LEFT, "*%d", X86Instruction->Scale);
		if (ShowDisplacement) X86_WRITE_RELATIVE_DISPLACEMENT()
		APPENDB(']');
	}
	else // just a displacement
	{
		APPENDB('[');
		X86_WRITE_ABSOLUTE_DISPLACEMENT()
		APPENDB(']');
	}
}

void OutputBounds(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	assert(X86Instruction->HasSrcAddressing);
	assert(!(Operand->Length & 1));
	Operand->Length >>= 1;
	APPENDB('(');
	OutputAddress(Instruction, Operand, OperandIndex);
	APPENDS(", ");
	X86Instruction->Displacement += Operand->Length;
	OutputAddress(Instruction, Operand, OperandIndex);
	X86Instruction->Displacement -= Operand->Length;
	APPENDB(')');
	Operand->Length <<= 1;
}

void OutputGeneral(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	if ((X86Instruction->HasDstAddressing && X86Instruction->DstAddressIndex == OperandIndex) ||
		(X86Instruction->HasSrcAddressing && X86Instruction->SrcAddressIndex == OperandIndex))
	{
		OutputAddress(Instruction, Operand, OperandIndex);
	}
	else
	{
		APPENDS(X86_Registers[Operand->Register]);
	}
}

void OutputDescriptor(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	assert(X86Instruction->HasSrcAddressing || X86Instruction->HasDstAddressing);
	OutputAddress(Instruction, Operand, OperandIndex);
}

void OutputPackedReal(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	if ((X86Instruction->HasDstAddressing && X86Instruction->DstAddressIndex == OperandIndex) ||
		(X86Instruction->HasSrcAddressing && X86Instruction->SrcAddressIndex == OperandIndex))
	{
		OutputAddress(Instruction, Operand, OperandIndex);
	}
	else
	{
		APPENDS(X86_Registers[Operand->Register]);
	}
}

void OutputPackedBCD(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	if ((X86Instruction->HasDstAddressing && X86Instruction->DstAddressIndex == OperandIndex) ||
		(X86Instruction->HasSrcAddressing && X86Instruction->SrcAddressIndex == OperandIndex))
	{
		OutputAddress(Instruction, Operand, OperandIndex);
	}
	else
	{
		APPENDS(X86_Registers[Operand->Register]);
	}
}

void OutputScalarReal(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	if ((X86Instruction->HasDstAddressing && X86Instruction->DstAddressIndex == OperandIndex) ||
		(X86Instruction->HasSrcAddressing && X86Instruction->SrcAddressIndex == OperandIndex))
	{
		OutputAddress(Instruction, Operand, OperandIndex);
	}
	else
	{
		APPENDS(X86_Registers[Operand->Register]);
	}
}

void OutputScalarGeneral(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	if (Operand->Type == OPTYPE_FLOAT)
	{
		OutputScalarReal(Instruction, Operand, OperandIndex);
	}
	else
	{
		OutputGeneral(Instruction, Operand, OperandIndex);
	}
}

void OutputFPUEnvironment(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	assert(X86Instruction->HasSrcAddressing || X86Instruction->HasDstAddressing);
	OutputAddress(Instruction, Operand, OperandIndex);
}

void OutputFPUState(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	assert(X86Instruction->HasSrcAddressing || X86Instruction->HasDstAddressing);
	OutputAddress(Instruction, Operand, OperandIndex);
}

void OutputCPUState(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	assert(X86Instruction->HasSrcAddressing);
	OutputAddress(Instruction, Operand, OperandIndex);
}

void OutputSegOffset(INSTRUCTION *Instruction, INSTRUCTION_OPERAND *Operand, U32 OperandIndex)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	assert(X86Instruction->HasSrcAddressing);
	OutputAddress(Instruction, Operand, OperandIndex);	
}

////////////////////////////////////////////////////////////
// Prologue support
////////////////////////////////////////////////////////////

typedef struct _PROLOGUE
{
	char *Data;
	U32 Length;
} PROLOGUE;

PROLOGUE StandardPrologues[] =
{
	{ "\x55\x8b\xec", 3 },
	{ "\x55\x89\xe5", 3 },
	{ "\x83\xec", 2 },
	{ "\x81\xec", 2 },
	// TODO: add AMD64 prologues
	// TODO: add VS2003/VS2003 prologues
	// TODO: add any unique prologues from other compilers
	{ NULL, 0 }
};

// Find the first function between StartAddress and EndAddress
// 
// This will match a standard prologue and then analyze the following instructions to verify
// it is a valid function
U8 *X86_FindFunctionByPrologue(INSTRUCTION *Instruction, U8 *StartAddress, U8 *EndAddress, U32 Flags)
{
	assert(0); // TODO
	return NULL;
}

//////////////////////////////////////////////////////////
// Instruction decoder
//////////////////////////////////////////////////////////

BOOL X86_GetInstruction(INSTRUCTION *Instruction, U8 *Address, U32 Flags)
{
	BOOL SpecialExtension = FALSE;
	U8 Opcode = 0, OpcodeExtension = 0, Group = 0, SSE_Prefix = 0, Suffix;
	U32 i = 0, Result = 0, tmpScale;
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	X86_OPCODE *X86Opcode;
#ifdef TEST_DISASM
	U32 InstructionLength = 0;
#endif
	INSTRUCTION_OPERAND *Operand, *Operand1 = NULL;
	DISASSEMBLER *Disassembler = Instruction->Disassembler;
	BOOL Decode = Flags & DISASM_DECODE;
	BOOL Disassemble = Flags & DISASM_DISASSEMBLE;
	BOOL SuppressErrors = Flags & DISASM_SUPPRESSERRORS;

	if (Disassemble && !Decode)
	{
		assert(0);
		Decode = TRUE;
	}

	if (!Address || !X86_InitInstruction(Instruction))
	{
		assert(0);
		goto abort;
	}

	assert(Instruction->Address == Address);
	assert(!Instruction->StringIndex && !Instruction->Length);

	Disassembler->Stage1Count++;
	if (Flags & DISASM_ALIGNOUTPUT) Instruction->StringAligned = TRUE;

	//
	// Get prefixes or three byte opcode
	//
	while (TRUE)
	{
		Opcode = *Address;
		INSTR_INC(1); // increment Instruction->Length and address
		X86Opcode = &X86_Opcodes_1[Opcode];

		// Handle a misplaced REX prefix -- AMD64 manual says it is just ignored
		if (IS_AMD64() && (Opcode >= REX_PREFIX_START && Opcode <= REX_PREFIX_END) && X86_PREFIX((&X86_Opcodes_1[*Address])))
		{
			if (!Instruction->AnomalyOccurred)
			{
				if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: REX prefix before legacy prefix 0x%02X\n", VIRTUAL_ADDRESS, Opcode);
				Instruction->AnomalyOccurred = TRUE;
			}
			continue;
		}
		
		if (X86_PREFIX(X86Opcode))
		{
			if (!Instruction->AnomalyOccurred)
			{
				for (i = 0; i < Instruction->PrefixCount; i++)
				{
					if (Instruction->Prefixes[i] == Opcode)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Duplicate prefix 0x%02X\n", VIRTUAL_ADDRESS, Opcode);
						Instruction->AnomalyOccurred = TRUE;
						break;
					}
				}
			}

			switch (Opcode)
			{
				case PREFIX_REPNE: // may be three byte opcode
					SSE_Prefix = Opcode;
					if (!Instruction->AnomalyOccurred && X86Instruction->HasRepeatWhileEqualPrefix)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Conflicting prefix\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					Instruction->Repeat = TRUE;
					X86Instruction->HasRepeatWhileEqualPrefix = FALSE;
					X86Instruction->HasRepeatWhileNotEqualPrefix = TRUE;
					break;
				case PREFIX_REP: // may be three byte opcode
					SSE_Prefix = Opcode;
					if (!Instruction->AnomalyOccurred && X86Instruction->HasRepeatWhileNotEqualPrefix)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Conflicting prefix\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}

					Instruction->Repeat = TRUE;
					X86Instruction->HasRepeatWhileNotEqualPrefix = FALSE;
					X86Instruction->HasRepeatWhileEqualPrefix = TRUE;
					break;

				case PREFIX_OPERAND_SIZE: // may be three byte opcode
					SSE_Prefix = Opcode;
					if (!Instruction->AnomalyOccurred && X86Instruction->HasOperandSizePrefix)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Conflicting prefix\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					
					if (X86Instruction->HasOperandSizePrefix) break;
					else X86Instruction->HasOperandSizePrefix = TRUE;
					switch (X86Instruction->OperandSize)
					{
						case 4: X86Instruction->OperandSize = 2; break;
						case 2: X86Instruction->OperandSize = 4; break;
						default: assert(0); goto abort;
					}
					break;

				case PREFIX_ADDRESS_SIZE:
					if (!Instruction->AnomalyOccurred && X86Instruction->HasAddressSizePrefix)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Conflicting prefix\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}

					if (X86Instruction->HasAddressSizePrefix) break;
					else X86Instruction->HasAddressSizePrefix = TRUE;
					switch (X86Instruction->AddressSize)
					{
						case 8:
							X86Instruction->AddressSize = 4;
							break;
						case 4:
							assert(!IS_AMD64()); // this should not be possible
							X86Instruction->AddressSize = 2;
							break;
						case 2:
							X86Instruction->AddressSize = 4;
							break;
						default: 
							assert(0); goto abort;
					}
					break;

				case PREFIX_SEGMENT_OVERRIDE_ES:
					SANITY_CHECK_SEGMENT_OVERRIDE();
					if (!IS_AMD64())
					{
						X86Instruction->HasSegmentOverridePrefix = TRUE;
						X86Instruction->Segment = SEG_ES;
					}
					else if (!Instruction->AnomalyOccurred)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Meaningless segment override\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					break;
				case PREFIX_SEGMENT_OVERRIDE_CS:
					SANITY_CHECK_SEGMENT_OVERRIDE();
					if (!IS_AMD64())
					{
						X86Instruction->HasSegmentOverridePrefix = TRUE;
						X86Instruction->Segment = SEG_CS;  
					}
					else if (!Instruction->AnomalyOccurred)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Meaningless segment override\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					break;
				case PREFIX_SEGMENT_OVERRIDE_SS:
					SANITY_CHECK_SEGMENT_OVERRIDE();
					if (!IS_AMD64())
					{
						X86Instruction->HasSegmentOverridePrefix = TRUE;
						X86Instruction->Segment = SEG_SS;
					}
					else if (!Instruction->AnomalyOccurred)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Meaningless segment override\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					break;
				case PREFIX_SEGMENT_OVERRIDE_DS:
					SANITY_CHECK_SEGMENT_OVERRIDE();
					if (!IS_AMD64())
					{
						X86Instruction->HasSegmentOverridePrefix = TRUE;
						X86Instruction->Segment = SEG_DS;
					}
					else if (!Instruction->AnomalyOccurred)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Meaningless segment override\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					break;
				case PREFIX_SEGMENT_OVERRIDE_FS:
					SANITY_CHECK_SEGMENT_OVERRIDE();
					X86Instruction->HasSegmentOverridePrefix = TRUE;
					X86Instruction->Segment = SEG_FS;
					break;
				case PREFIX_SEGMENT_OVERRIDE_GS:
					SANITY_CHECK_SEGMENT_OVERRIDE();
					X86Instruction->HasSegmentOverridePrefix = TRUE;
					X86Instruction->Segment = SEG_GS;
					break;

				case PREFIX_LOCK:
					if (!Instruction->AnomalyOccurred && X86Instruction->HasLockPrefix)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Conflicting prefix\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					X86Instruction->HasLockPrefix = TRUE;
					break;

				default:
					assert(0);
					goto abort;
			}

			if (Instruction->PrefixCount >= X86_MAX_INSTRUCTION_LEN)
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Reached maximum prefix count %d\n", VIRTUAL_ADDRESS, X86_MAX_PREFIX_LENGTH);
				goto abort;
			}
			else if (Instruction->PrefixCount == X86_MAX_PREFIX_LENGTH)
			{
				if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Reached maximum prefix count %d\n", VIRTUAL_ADDRESS, X86_MAX_PREFIX_LENGTH);
				Instruction->AnomalyOccurred = TRUE;
			}

			assert(Instruction->AnomalyOccurred || Instruction->PrefixCount < X86_MAX_PREFIX_LENGTH);
			Instruction->Prefixes[Instruction->PrefixCount] = Opcode;
			Instruction->PrefixCount++;
			//DISASM_OUTPUT(("[0x%08I64X] Prefix 0x%02X (prefix count %d)\n", VIRTUAL_ADDRESS, Opcode, Instruction->PrefixCount));
		}
		else
		{
			break;
		}
	}

	// Check for REX opcode
	// This is checked here instead of the prefix loop above because it must be the
	// last prefix
	if (IS_AMD64() && (Opcode >= REX_PREFIX_START && Opcode <= REX_PREFIX_END))
	{
		if (Instruction->PrefixCount >= X86_MAX_INSTRUCTION_LEN)
		{
			if (!SuppressErrors) printf("[0x%08I64X] ERROR: Reached maximum prefix count %d\n", VIRTUAL_ADDRESS, X86_MAX_PREFIX_LENGTH);
			goto abort;
		}
		else if (!Instruction->AnomalyOccurred && Instruction->PrefixCount == AMD64_MAX_PREFIX_LENGTH)
		{
			if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Reached maximum prefix count %d\n", VIRTUAL_ADDRESS, X86_MAX_PREFIX_LENGTH);
			Instruction->AnomalyOccurred = TRUE;
		}

		assert(Instruction->AnomalyOccurred || Instruction->PrefixCount < AMD64_MAX_PREFIX_LENGTH);

		Instruction->Prefixes[Instruction->PrefixCount] = Opcode;
		Instruction->PrefixCount++;
		X86Instruction->rex_b = Opcode;
		SET_REX(X86Instruction->rex, X86Instruction->rex_b);
		DISASM_OUTPUT(("[0x%08I64X] REX prefix 0x%02X (prefix count %d, w=%d, r=%d, x=%d, b=%d)\n", VIRTUAL_ADDRESS, Opcode, Instruction->PrefixCount, X86Instruction->rex.w, X86Instruction->rex.r, X86Instruction->rex.x, X86Instruction->rex.b));

		assert(X86Instruction->AddressSize >= 4);
		if (X86Instruction->rex.w)
		{
			X86Instruction->OperandSize = 8;
			X86Instruction->HasOperandSizePrefix = FALSE;
		}
		else if (X86Instruction->HasOperandSizePrefix)
		{
			assert(X86Instruction->OperandSize == 2);
		}
		else if (X86Instruction->rex_b == REX_PREFIX_START)
		{
			if (!Instruction->AnomalyOccurred)
			{
				if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: meaningless REX prefix used\n", VIRTUAL_ADDRESS);
				Instruction->AnomalyOccurred = TRUE;
			}
			X86Instruction->rex_b = 0;
		}

		Opcode = *Address;
		INSTR_INC(1); // increment Instruction->Length and address

		X86Opcode = &X86_Opcodes_1[Opcode];
		assert(!X86_PREFIX(X86Opcode));
	}
	//DISASM_OUTPUT(("[0x%08I64X] OperandSize = %d, AddressSize = %d\n", VIRTUAL_ADDRESS, X86Instruction->OperandSize, X86Instruction->AddressSize));
	Instruction->LastOpcode = Opcode;
	Instruction->OpcodeAddress = Address-1;

	if (X86_INVALID(X86Opcode))
	{
		if (!SuppressErrors) printf("[0x%08I64X] ERROR: Invalid opcode 0x%02X\n", VIRTUAL_ADDRESS, Opcode);
		goto abort;
	}

	if (Opcode == X86_TWO_BYTE_OPCODE)
	{
		//
		// Handle case that it is a group (with opcode extension), floating point, or two byte opcode
		//
		assert(!Instruction->OpcodeLength);
		Instruction->LastOpcode = Opcode = *Address;
		INSTR_INC(1); // increment Instruction->Length and address
		assert(X86Opcode->Table == X86_Opcodes_2);
		X86Opcode = &X86_Opcodes_2[Opcode];

		//
		// Check for errors
		//
		if (X86_INVALID(X86Opcode))
		{
			if (!SuppressErrors) printf("[0x%08I64X] ERROR: Invalid two byte opcode 0x%02X 0x%02X\n", VIRTUAL_ADDRESS, X86_TWO_BYTE_OPCODE, Opcode);
			goto abort;
		}
		
		if (X86Instruction->AddressSize == 8)
		{
			if (X86_Invalid_Addr64_2[Opcode])
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Opcode 0x%02X 0x%02X (\"%s\") illegal in 64-bit mode\n", VIRTUAL_ADDRESS, X86_TWO_BYTE_OPCODE, Opcode, X86Opcode->Mnemonic);
				goto abort;
			}
#if 0
			if (X86Instruction->rex_b &&
					(GET_REX_B(X86Instruction->rex_b) && !GET_REX_B(X86_REX_2[Opcode]) ||
					 GET_REX_X(X86Instruction->rex_b) && !GET_REX_X(X86_REX_2[Opcode]) ||
					 GET_REX_R(X86Instruction->rex_b) && !GET_REX_R(X86_REX_2[Opcode]) ||
					 GET_REX_W(X86Instruction->rex_b) && !GET_REX_W(X86_REX_2[Opcode])))
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Illegal REX prefix 0x%02X for opcode 0x%02X 0x%02X\n", VIRTUAL_ADDRESS, X86Instruction->rex_b, X86_TWO_BYTE_OPCODE, Opcode);
				assert(0);
				goto abort;
			}
#endif
		}

		if (X86Instruction->OperandSize == 2 && X86_Invalid_Op16_2[Opcode])
		{
			if (!SuppressErrors) printf("[0x%08I64X] ERROR: Opcode 0x%02X 0x%02X (\"%s\") illegal with 16-bit operand size\n", VIRTUAL_ADDRESS, X86_TWO_BYTE_OPCODE, Opcode, X86Opcode->Mnemonic);
			goto abort;
		}

		X86Instruction->HasModRM = X86_ModRM_2[Opcode];
		if (X86Instruction->HasModRM) X86Instruction->modrm_b = *Address;
		Instruction->OpcodeBytes[0] = X86_TWO_BYTE_OPCODE;
		Instruction->OpcodeBytes[1] = Opcode;
		Instruction->OpcodeLength = 2;

		if (X86_SPECIAL_EXTENSION(X86Opcode))
		{
			DISASM_OUTPUT(("[0x%08I64X] Special opcode extension 0x%02X 0x%02X\n", VIRTUAL_ADDRESS, X86_TWO_BYTE_OPCODE, Opcode));
			SpecialExtension = TRUE;
			goto HasSpecialExtension;
		}
		else if (SSE_Prefix && !X86_INVALID(&X86_SSE[Opcode])) // SSEx instruction
		{
			Instruction->OpcodeLength = 3;
			Instruction->OpcodeBytes[2] = SSE_Prefix;
			assert(Instruction->OpcodeBytes[1] == Opcode);

			// Since the prefix was really an opcode extension, remove it from
			// the prefix list
			for (i = 0; i < Instruction->PrefixCount; i++)
			{
				if (Instruction->Prefixes[i]) break;
			}
			assert(i != Instruction->PrefixCount);
			Instruction->PrefixCount--;
			Instruction->Prefixes[i] = 0;

			// Slide any prefixes following the removed prefix down by 1
			memmove(&Instruction->Prefixes[i], &Instruction->Prefixes[i+1], Instruction->PrefixCount-i);
			Instruction->Prefixes[Instruction->PrefixCount] = 0;
			Instruction->Repeat = FALSE;
			X86Instruction->HasRepeatWhileEqualPrefix = FALSE;
			X86Instruction->HasRepeatWhileNotEqualPrefix = FALSE;
			X86Instruction->HasOperandSizePrefix = FALSE;
			if (SSE_Prefix == PREFIX_OPERAND_SIZE)
			{
				if (IS_AMD64() && X86Instruction->rex.w) X86Instruction->OperandSize = 8;
				else X86Instruction->OperandSize = 4;
			}

			if (IS_X86_16())
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: SSE invalid in 16-bit mode\n", VIRTUAL_ADDRESS);
				goto abort;
			}
		
			assert(X86Instruction->HasModRM);
			switch (SSE_Prefix)
			{
				case PREFIX_OPERAND_SIZE: X86Opcode = &X86_SSE[0x000+Opcode]; break;
				case PREFIX_REPNE: X86Opcode = &X86_SSE[0x100+Opcode]; break;
				case PREFIX_REP: X86Opcode = &X86_SSE[0x200+Opcode]; break;
			}

			if (X86_INVALID(X86Opcode))
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Illegal SSE instruction opcode 0x%02X 0x%02X + prefix 0x%02X\n", VIRTUAL_ADDRESS, Instruction->OpcodeBytes[0], Instruction->OpcodeBytes[1], Instruction->OpcodeBytes[2]);
				goto abort;
			}
			else if (X86_EXTENDED_OPCODE(X86Opcode))
			{
				// SSE in group (13, 14, or 15)
				OpcodeExtension = GET_MODRM_EXT(X86Instruction->modrm_b);
				Group = X86_Groups_2[Opcode];
				X86Instruction->Group = (U8)Group;
				assert(Group >= 13 && Group <= 15 && X86Opcode->Table);
				switch (SSE_Prefix)
				{
					case PREFIX_OPERAND_SIZE: X86Opcode = &X86Opcode->Table[0x00+OpcodeExtension]; break;
					case PREFIX_REPNE: X86Opcode = &X86Opcode->Table[0x08+OpcodeExtension]; break;
					case PREFIX_REP: X86Opcode = &X86Opcode->Table[0x10+OpcodeExtension]; break;
				}

				if (X86_INVALID(X86Opcode))
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: Illegal SSE instruction opcode 0x%02X 0x%02X + prefix 0x%02X + extension %d\n", VIRTUAL_ADDRESS, Instruction->OpcodeBytes[0], Instruction->OpcodeBytes[1], Instruction->OpcodeBytes[2], OpcodeExtension);
					goto abort;
				}
			}

			Instruction->Repeat = FALSE;
			X86Instruction->HasRepeatWhileEqualPrefix = FALSE;
			X86Instruction->HasRepeatWhileNotEqualPrefix = FALSE;
			X86Instruction->HasOperandSizePrefix = FALSE;
			switch (X86_GET_CATEGORY(X86Opcode))
			{
				case ITYPE_SSE: case ITYPE_SSE2: case ITYPE_SSE3: break;
				default: assert(0); goto abort;
			}
		}
		else if (X86_EXTENDED_OPCODE(X86Opcode)) // 2 byte group
		{
			assert(!X86Opcode->MnemonicFlags);
			OpcodeExtension = GET_MODRM_EXT(X86Instruction->modrm_b);

			assert(X86Opcode->Table);
			X86Opcode = &X86Opcode->Table[OpcodeExtension];
			if (X86_INVALID(X86Opcode))
			{
				Instruction->Length++;
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Invalid group opcode 0x%02X 0x%02X extension 0x%02X\n", VIRTUAL_ADDRESS, X86_TWO_BYTE_OPCODE, Opcode, OpcodeExtension);
				goto abort;
			}

			assert(!X86_SPECIAL_EXTENSION(X86Opcode));
			Group = X86_Groups_2[Opcode];
			X86Instruction->Group = (U8)Group;
			assert(Group > 0 && Group <= 19);
			assert(X86Opcode->Mnemonic);
			DISASM_OUTPUT(("[0x%08I64X] Group %d (bytes 0x%02X 0x%02X) extension 0x%02X (\"%s\")\n", VIRTUAL_ADDRESS, Group, X86_TWO_BYTE_OPCODE, Opcode, OpcodeExtension, X86Opcode->Mnemonic));
		}
		else
		{
			assert(X86Opcode->Mnemonic);
			DISASM_OUTPUT(("[0x%08I64X] Two byte opcode 0x%02X 0x%02X (\"%s\")\n", VIRTUAL_ADDRESS, X86_TWO_BYTE_OPCODE, Opcode, X86Opcode->Mnemonic));
			X86Instruction->HasModRM = X86_ModRM_2[Opcode];
			if (X86Instruction->HasModRM) X86Instruction->modrm_b = *Address;
		}
	}
	else // 1-byte opcode
	{
		if (X86Instruction->AddressSize == 8)
		{
			if (X86_Invalid_Addr64_1[Opcode])
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Opcode 0x%02X (\"%s\") illegal in 64-bit mode\n", VIRTUAL_ADDRESS, Opcode, X86Opcode->Mnemonic);
				goto abort;
			}

#if 0
			if (X86Instruction->rex_b &&
				(GET_REX_B(X86Instruction->rex_b) && !GET_REX_B(X86_REX_1[Opcode]) ||
				 GET_REX_X(X86Instruction->rex_b) && !GET_REX_X(X86_REX_1[Opcode]) ||
				 GET_REX_R(X86Instruction->rex_b) && !GET_REX_R(X86_REX_1[Opcode]) ||
				 GET_REX_W(X86Instruction->rex_b) && !GET_REX_W(X86_REX_1[Opcode])))
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Illegal REX prefix 0x%02X for opcode 0x%02X\n", VIRTUAL_ADDRESS, X86Instruction->rex_b, Opcode);
				assert(0);
				goto abort;
			}
#endif
		}

		if (X86Instruction->OperandSize == 2 && X86_Invalid_Op16_1[Opcode])
		{
			if (!SuppressErrors) printf("[0x%08I64X] ERROR: Opcode 0x%02X (\"%s\") illegal with 16-bit operand size\n", VIRTUAL_ADDRESS, Opcode, X86Opcode->Mnemonic);
			goto abort;
		}

		Instruction->OpcodeBytes[0] = Opcode;
		Instruction->OpcodeLength = 1;
		X86Instruction->HasModRM = X86_ModRM_1[Opcode];
		if (X86Instruction->HasModRM) X86Instruction->modrm_b = *Address;

		if (X86_EXTENDED_OPCODE(X86Opcode)) // a group
		{
			assert(X86Instruction->HasModRM);
			OpcodeExtension = GET_MODRM_EXT(*Address); // leave Address pointing at ModRM byte

			if (X86_SPECIAL_EXTENSION(X86Opcode))
			{
				DISASM_OUTPUT(("[0x%08I64X] Special opcode extension 0x%02X 0x%02X\n", VIRTUAL_ADDRESS, X86_TWO_BYTE_OPCODE, Opcode));
				SpecialExtension = TRUE;
				goto HasSpecialExtension;
			}

			assert(X86Opcode->Table);
			X86Opcode = &X86Opcode->Table[OpcodeExtension];
			if (X86_INVALID(X86Opcode))
			{
				Instruction->Length++;
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Invalid group opcode 0x%02X extension 0x%02X\n", VIRTUAL_ADDRESS, Opcode, OpcodeExtension);
				goto abort;
			}

			Group = X86_Groups_1[Opcode];
			X86Instruction->Group = (U8)Group;
			DISASM_OUTPUT(("[0x%08I64X] Group %d (byte 0x%02X) extension 0x%02X (\"%s\")\n", VIRTUAL_ADDRESS, Group, Opcode, OpcodeExtension, X86Opcode->Mnemonic));
			assert(Group > 0 && Group <= 17);
			assert(X86Opcode->Mnemonic);
		}
		else
		{
			if (X86_SPECIAL_EXTENSION(X86Opcode))
			{
				DISASM_OUTPUT(("[0x%08I64X] Special opcode extension 0x%02X\n", VIRTUAL_ADDRESS, Opcode));
				SpecialExtension = TRUE;
				goto HasSpecialExtension;
			}

			DISASM_OUTPUT(("[0x%08I64X] One byte opcode 0x%02X (\"%s\")\n", VIRTUAL_ADDRESS, Opcode, X86Opcode->Mnemonic));
		}
	}

HasSpecialExtension:
	if (SpecialExtension)
	{
		if (X86Opcode->MnemonicFlags & ITYPE_EXT_MODRM)
		{
			assert(X86Opcode->Table);
			assert(Instruction->OpcodeLength == 2);
			assert(X86Instruction->HasModRM);
			X86Opcode = &X86Opcode->Table[*Address];
			if (X86_INVALID(X86Opcode))
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Illegal opcode 0x%02X 0x%02X + modrm 0x%02X\n", VIRTUAL_ADDRESS, Instruction->OpcodeBytes[0], Instruction->OpcodeBytes[1], *Address);
				goto abort;
			}
			else if (X86_EXTENDED_OPCODE(X86Opcode))
			{
				assert(!X86Opcode->MnemonicFlags);
				OpcodeExtension = GET_MODRM_EXT(X86Instruction->modrm_b);

				assert(X86Opcode->Table);
				X86Opcode = &X86Opcode->Table[OpcodeExtension];
				if (X86_INVALID(X86Opcode))
				{
					Instruction->Length++;
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: Invalid group opcode 0x%02X 0x%02X extension 0x%02X\n", VIRTUAL_ADDRESS, X86_TWO_BYTE_OPCODE, Opcode, OpcodeExtension);
					goto abort;
				}

				assert(!X86_SPECIAL_EXTENSION(X86Opcode));
				Group = X86_Groups_2[Opcode];
				X86Instruction->Group = (U8)Group;
				assert(Group > 0 && Group <= 19);
				assert(X86Opcode->Mnemonic);
				DISASM_OUTPUT(("[0x%08I64X] Group %d (bytes 0x%02X 0x%02X) extension 0x%02X (\"%s\")\n", VIRTUAL_ADDRESS, Group, X86_TWO_BYTE_OPCODE, Opcode, OpcodeExtension, X86Opcode->Mnemonic));
			}
			else if (!X86_OPERAND_COUNT(X86Opcode))
			{
				INSTR_INC(1); // increment Instruction->Length and address
			}
		}
		else if (X86Opcode->MnemonicFlags & ITYPE_EXT_FPU)
		{
			assert(X86Opcode->Table);		
			if (X86Instruction->modrm_b < 0xC0)
			{
				// It is an opcode extension, use the X86Opcode->Table
				OpcodeExtension = GET_MODRM_EXT(X86Instruction->modrm_b);
				X86Opcode = &X86Opcode->Table[OpcodeExtension];
			}
			else
			{
				// The whole ModRM byte is used, these start at index 0x08 in X86Opcode->Table
				OpcodeExtension = (X86Instruction->modrm_b & 0x3F);
				X86Opcode = &X86Opcode->Table[0x08 + OpcodeExtension];
			}

			if (X86_INVALID(X86Opcode))
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Invalid FPU opcode 0x%02X + modrm extension 0x%02X (index 0x%02X)\n", VIRTUAL_ADDRESS, Opcode, X86Instruction->modrm_b, 0x08 + OpcodeExtension);
				goto abort;
			}

			DISASM_OUTPUT(("[0x%08I64X] FPU instruction is (\"%s\"): 0x%02X + modrm 0x%02X (index 0x%02X)\n", VIRTUAL_ADDRESS, X86Opcode->Mnemonic, Opcode, X86Instruction->modrm_b, 0x08 + OpcodeExtension));
			if (!X86_OPERAND_COUNT(X86Opcode)) INSTR_INC(1); // increment Instruction->Length and address
		}
		else if (X86Opcode->MnemonicFlags & ITYPE_EXT_SUFFIX)
		{
			if (X86Instruction->HasOperandSizePrefix)
			{
				if (!Instruction->AnomalyOccurred && X86Opcode->Table == X86_3DNOW_0F)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: operand size prefix used with 3DNOW instruction\n", VIRTUAL_ADDRESS);
					Instruction->AnomalyOccurred = TRUE;
				}
				X86Instruction->HasOperandSizePrefix = FALSE;
				X86Instruction->OperandSize = 4;
			}
			Instruction->OperandCount = X86_OPERAND_COUNT(X86Opcode);
			assert(Instruction->OpcodeLength == 2 && X86Instruction->HasModRM && Instruction->OperandCount == 2);
			memcpy(&X86Instruction->Opcode, X86Opcode, sizeof(X86_OPCODE));
			Instruction->Operands[0].Flags = X86Opcode->OperandFlags[0] & X86_OPFLAGS_MASK;
			Instruction->Operands[1].Flags = X86Opcode->OperandFlags[1] & X86_OPFLAGS_MASK;
			Instruction->Operands[2].Flags = X86Opcode->OperandFlags[2] & X86_OPFLAGS_MASK;
			assert(Address == Instruction->Address + Instruction->Length);
			if (!SetOperands(Instruction, Address, Flags & DISASM_SUPPRESSERRORS)) goto abort;
			Suffix = Instruction->Address[Instruction->Length++];
			Instruction->OpcodeBytes[2] = Suffix;
			Instruction->OpcodeLength = 3;
			X86Opcode = &X86Opcode->Table[Suffix];
			
			if (X86_INVALID(X86Opcode))
			{
				if (!SuppressErrors) printf("[0x%08I64X] ERROR: Illegal opcode 0x%02X 0x%02X + suffix 0x%02X\n", VIRTUAL_ADDRESS, Instruction->OpcodeBytes[0], Instruction->OpcodeBytes[1], Suffix);
				goto abort;
			}
			assert(Instruction->Length >= 4 + Instruction->PrefixCount);
		}
		else if (X86Opcode->MnemonicFlags & ITYPE_EXT_64)
		{
			assert(X86Opcode->Table);
			if (IS_AMD64()) X86Opcode = &X86Opcode->Table[1];
			else X86Opcode = &X86Opcode->Table[0];
			assert(!X86_INVALID(X86Opcode));
		}
	}

	// Detect incompatibilities	
	if (IS_X86_16() && X86Opcode->CPU > CPU_I386)
	{
		if (!SuppressErrors) printf("[0x%08I64X] ERROR: Instruction \"%s\" (opcode 0x%02X) can't be used in 16-bit X86\n", VIRTUAL_ADDRESS, X86Opcode->Mnemonic, Instruction->LastOpcode);
		goto abort;
	}
	if (!IS_AMD64() && X86Opcode->CPU >= CPU_AMD64)
	{
		if (!SuppressErrors) printf("[0x%08I64X] ERROR: Instruction \"%s\" (opcode 0x%02X) can only be used in X86-64\n", VIRTUAL_ADDRESS, X86Opcode->Mnemonic, Instruction->LastOpcode);
		goto abort;
	}

	// Copy the opcode into the local structure and set the fields 
	assert(Instruction->OpcodeLength && !X86_INVALID(X86Opcode));
	memcpy(&X86Instruction->Opcode, X86Opcode, sizeof(X86_OPCODE));
	Instruction->Groups |= X86_GET_CATEGORY(X86Opcode);
	assert(Instruction->Groups);
	Instruction->Type |= X86_GET_TYPE(X86Opcode);
	assert((U32)Instruction->Type >= Instruction->Groups);
	Instruction->OperandCount = X86_OPERAND_COUNT(X86Opcode);

	//
	// Sanity check prefixes now that opcode is known and prefixes are resolved
	//

	// Instructions that implicitly reference the CS/DS can't have segment override prefixes
	switch (Instruction->Type)
	{
		case ITYPE_PUSHF: case ITYPE_POPF:
		case ITYPE_ENTER: case ITYPE_LEAVE:
			SANITY_CHECK_SEGMENT_OVERRIDE();
			X86Instruction->HasSegmentOverridePrefix = FALSE;
			X86Instruction->Segment = SEG_SS;
			break;
		case ITYPE_RET: case ITYPE_DEBUG: 
		case ITYPE_OFLOW: case ITYPE_TRAP: 
		case ITYPE_TRAPRET:
			SANITY_CHECK_SEGMENT_OVERRIDE();
			X86Instruction->HasSegmentOverridePrefix = FALSE;
			X86Instruction->Segment = SEG_CS;
			break;
	}

	// Check illegal prefixes used with FPU/MMX/SSEx
	if (Instruction->Groups & (ITYPE_FPU|ITYPE_MMX|ITYPE_SSE|ITYPE_SSE2|ITYPE_SSE3))
	{
		// Check for prefixes that produce unpredictable results
		for (i = 0; i < Instruction->PrefixCount; i++)
		{
			switch (Instruction->Prefixes[i])
			{
				case PREFIX_OPERAND_SIZE:
					switch (Instruction->Type)
					{
						case ITYPE_FSTOREENV: case ITYPE_FLOADENV: case ITYPE_FSAVE: case ITYPE_FRESTORE: continue;
						default: break;
					}

					if (!Instruction->AnomalyOccurred)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: operand size prefix used with FPU/MMX/SSEx\n", VIRTUAL_ADDRESS);
						goto abort;
					}
					X86Instruction->HasOperandSizePrefix = FALSE;
					if (X86Instruction->OperandSize == 2) X86Instruction->OperandSize = 2;
					break;

				case PREFIX_REPNE:
				case PREFIX_REP:
					if (Instruction->Groups & ITYPE_FPU) { assert(Instruction->Repeat); continue; }
					// The Intel manual says this results in unpredictable behavior -- it's not even
					// clear which SSE prefix is used as the third opcode byte in this case
					// (e.g., is it the first or last SSE prefix?)
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: rep/repne used with MMX/SSEx\n", VIRTUAL_ADDRESS);
					goto abort;

				default:
					break;
			}
		}
	}

	// Check for conflicts involving operand size
	if (IS_AMD64())
	{
		// Check for use of rex.w=1 with an operand size prefix
		if (X86Instruction->rex.w)
		{
			assert(X86Instruction->OperandSize == 8);
			for (i = 0; i < Instruction->PrefixCount; i++)
			{
				if (Instruction->Prefixes[i] == PREFIX_OPERAND_SIZE)
				{
					X86Instruction->HasOperandSizePrefix = FALSE;
					if (!Instruction->AnomalyOccurred)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: use of operand size prefix meaningless when REX.w=1\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}				
				}
			}
		}

		// Set default operand size to 64 instead of 32 for some instructions
		switch (Instruction->Type)
		{
			case ITYPE_PUSH: case ITYPE_POP: 
			case ITYPE_PUSHF: case ITYPE_POPF:
			case ITYPE_ENTER: case ITYPE_LEAVE:
			case ITYPE_CALL: case ITYPE_BRANCH:
			case ITYPE_LOOPCC: case ITYPE_RET:
				X86Instruction->HasDefault64Operand = TRUE;
				break;

			case ITYPE_SYSTEM:
				if (Instruction->OpcodeLength != 2) break;

				// lgdt/lidt/lldt/ltr
				if ((Instruction->LastOpcode == 0x00 || Instruction->LastOpcode == 0x01) && 
					(OpcodeExtension == 0x02 || OpcodeExtension == 0x03))
				{
					X86Instruction->HasDefault64Operand = TRUE;
				}
				break;

			default:
				break;
		}

		if (X86Instruction->HasDefault64Operand)
		{
			if (X86Instruction->rex.w)
			{
				if (!Instruction->AnomalyOccurred)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: use of REX.w is meaningless (default operand size is 64)\n", VIRTUAL_ADDRESS);
					Instruction->AnomalyOccurred = TRUE;
				}
				X86Instruction->rex_b &= ~8;
				X86Instruction->rex.w = 0;
			}

			if (X86Instruction->HasOperandSizePrefix)
			{
				assert(X86Instruction->OperandSize == 2);
				X86Instruction->HasDefault64Operand = FALSE;
			}
			else
			{
				assert(X86Instruction->OperandSize >= 4);
				X86Instruction->OperandSize = 8;
			}
		}
	}

	// Make sure rep/repe/repne is set correctly based on instruction
	if (Instruction->Repeat)
	{
		switch (Instruction->Type)
		{
			case ITYPE_IN:
			case ITYPE_OUT:
			case ITYPE_STRMOV:
			case ITYPE_STRSTOR:
			case ITYPE_STRLOAD:
				if (X86Instruction->HasRepeatWhileNotEqualPrefix)
				{
					if (!Instruction->AnomalyOccurred)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: REPNE should only be used with cmps/scas\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					// Treat it as just a "rep"
					X86Instruction->HasRepeatWhileNotEqualPrefix = FALSE;
					X86Instruction->HasRepeatWhileEqualPrefix = TRUE;
				}
				break;
			case ITYPE_STRCMP:
				break;
			default:
				if (!Instruction->AnomalyOccurred)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Repeat prefix used with non-string instruction\n", VIRTUAL_ADDRESS);
					Instruction->AnomalyOccurred = TRUE;
				}
				Instruction->Repeat = FALSE;
				X86Instruction->HasRepeatWhileEqualPrefix = FALSE;
				X86Instruction->HasRepeatWhileNotEqualPrefix = FALSE;
				break;
		}
	}

	if (Disassemble)
	{
		assert(!Instruction->StringIndex);
		if (X86Instruction->HasRepeatWhileEqualPrefix)
		{
			if (Instruction->Type == ITYPE_STRCMP) { APPENDS("repe "); }
			else { APPENDS("rep "); }
		}
		if (X86Instruction->HasRepeatWhileNotEqualPrefix) APPENDS("repne "); 
		if (X86Instruction->HasLockPrefix) APPENDS("lock "); 
		if (X86Instruction->HasBranchTakenPrefix) APPENDS("hinttake ");
		if (X86Instruction->HasBranchNotTakenPrefix) APPENDS("hintskip ");
		APPENDPAD(12);
		APPEND(OPCSTR, SIZE_LEFT, "%s", X86Opcode->Mnemonic);
		APPENDPAD(24);
	}

	if (Instruction->OperandCount)
	{
		Instruction->Operands[0].Flags = X86Opcode->OperandFlags[0] & X86_OPFLAGS_MASK;
		Instruction->Operands[1].Flags = X86Opcode->OperandFlags[1] & X86_OPFLAGS_MASK;
		Instruction->Operands[2].Flags = X86Opcode->OperandFlags[2] & X86_OPFLAGS_MASK;
		Address = SetOperands(Instruction, Address, Flags);
		if (!Address) goto abort;
		assert(!(Instruction->Operands[0].Flags & 0x7F));
		assert(!(Instruction->Operands[1].Flags & 0x7F));
		assert(!(Instruction->Operands[2].Flags & 0x7F));
	}

	Disassembler->Stage2Count++;

#ifdef TEST_DISASM
	//////////////////////////////////////////////////////////////////////
	// Test against other disassemblers
	//////////////////////////////////////////////////////////////////////

	if (IS_X86_32())
	{
		InstructionLength = X86_GetLength(Instruction, Instruction->Address);
		if (InstructionLength && Instruction->Length != InstructionLength)
		{
			printf("[0x%08I64X] WARNING: instruction lengths differ (%d vs %d)\n", VIRTUAL_ADDRESS, Instruction->Length, InstructionLength);
			DumpInstruction(Instruction, TRUE, TRUE);
			assert(0);
		}
	}
	else if (IS_AMD64())
	{
		// TODO: need other amd64 (x86-64) disassembler to test against
	}
	else if (IS_X86_16())
	{
		// TODO: need other x86 16-bit disassembler to test against
	}
#endif

	//////////////////////////////////////////////////////////////////////
	// Post-operand sanity checks
	//////////////////////////////////////////////////////////////////////

	if (!X86Instruction->HasDstAddressing && !X86Instruction->HasSrcAddressing)
	{
		if (X86Instruction->HasAddressSizePrefix)
		{
			if (!Instruction->AnomalyOccurred)
			{
				if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: address size prefix used with no addressing\n", VIRTUAL_ADDRESS);
				Instruction->AnomalyOccurred = TRUE;
			}
			X86Instruction->HasAddressSizePrefix = FALSE;
		}

		if (X86Instruction->HasSegmentOverridePrefix)
		{
			if (!Instruction->AnomalyOccurred)
			{
				if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: segment override used with no addressing\n", VIRTUAL_ADDRESS);
				Instruction->AnomalyOccurred = TRUE;
			}
			X86Instruction->HasSegmentOverridePrefix = FALSE;
		}	
	}

	// Detect use of unusual segments
	if (!Instruction->AnomalyOccurred && !IS_X86_16())
	{
		switch (X86Instruction->Segment)
		{
			case SEG_CS: case SEG_DS: case SEG_SS:
				break;
			case SEG_ES:
				switch (Instruction->Type)
				{
 					case ITYPE_IN: case ITYPE_STRMOV: case ITYPE_STRCMP: case ITYPE_STRSTOR:
						break;
					default:
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: use of unexpected segment ES\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
						break;
				}
				break;
			case SEG_FS:
				if (IS_X86_32() && !(Instruction->Groups & ITYPE_EXEC)) break;
				if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: use of unexpected segment FS\n", VIRTUAL_ADDRESS);
				Instruction->AnomalyOccurred = TRUE;
				break;
			case SEG_GS:
				if (IS_AMD64() && !(Instruction->Groups & ITYPE_EXEC)) break;
				if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: use of unexpected segment GS\n", VIRTUAL_ADDRESS);
				Instruction->AnomalyOccurred = TRUE;
				break;
			default:
				if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: unexpected segment 0x%02X\n", VIRTUAL_ADDRESS, X86Instruction->Selector);
				Instruction->AnomalyOccurred = TRUE;
				break;
		}
	}

	if ((X86Opcode->OperandFlags[0] & OP_COND_EXEC) == OP_COND_EXEC)
	{
 		assert(Instruction->Type == ITYPE_BRANCHCC || Instruction->Type == ITYPE_LOOPCC);
		for (i = 0; i < Instruction->PrefixCount; i++)
		{
			switch (Instruction->Prefixes[i])
			{
				case PREFIX_BRANCH_NOT_TAKEN:
					if (!Instruction->AnomalyOccurred && X86Instruction->Segment != SEG_CS)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Segment override used with conditional branch\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					X86Instruction->HasSegmentOverridePrefix = FALSE;
					X86Instruction->Segment = SEG_CS;
					X86Instruction->HasBranchNotTakenPrefix = TRUE;
					break;
				case PREFIX_BRANCH_TAKEN:
					if (!Instruction->AnomalyOccurred && X86Instruction->Segment != SEG_DS)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Segment override used with conditional branch\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					X86Instruction->HasSegmentOverridePrefix = FALSE;
					X86Instruction->Segment = SEG_CS;
					X86Instruction->HasBranchTakenPrefix = TRUE;
					break;
			}
		}
	}

	//
	// If lock prefix is enabled, verify it is valid
	//
	if (X86Instruction->HasLockPrefix && 
		!IsValidLockPrefix(X86Instruction, Opcode, Instruction->OpcodeLength, Group, OpcodeExtension))
	{
		if (!SuppressErrors) printf("[0x%08I64X] ERROR: Illegal use of lock prefix for instruction \"%s\"\n", VIRTUAL_ADDRESS, X86Opcode->Mnemonic);
		goto abort;
	}

	//////////////////////////////////////////////////////////////////////
	// Generate disassembly output
	//////////////////////////////////////////////////////////////////////

	if (Disassemble)
	{
		if ((Flags & DISASM_SHOWFLAGS) && 
			(X86Instruction->Opcode.Preconditions || X86Instruction->Opcode.FlagsChanged || X86Instruction->Opcode.ResultsIfTrue))
		{
			APPENDPAD(124);
			if (X86Instruction->Opcode.Preconditions)
			{
				Result = X86Instruction->Opcode.Preconditions;
				APPENDS("COND:{ ");
				if (Result & COND_L) APPENDS("L ");
				if (Result & COND_NL) APPENDS("NL ");
				if (Result & COND_LE) APPENDS("LE ");
				if (Result & COND_NLE) APPENDS("NLE ");
				if (Result & COND_G) APPENDS("G ");
				if (Result & COND_NG) APPENDS("NG ");
				if (Result & COND_GE) APPENDS("GE ");
				if (Result & COND_NGE) APPENDS("NGE ");
				if (Result & COND_A) APPENDS("A ");
				if (Result & COND_NA) APPENDS("NA ");
				if (Result & COND_AE) APPENDS("AE ");
				if (Result & COND_NAE) APPENDS("NAE ");
				if (Result & COND_B) APPENDS("B ");
				if (Result & COND_NB) APPENDS("NB ");
				if (Result & COND_BE) APPENDS("BE ");
				if (Result & COND_NBE) APPENDS("NBE ");
				if (Result & COND_E) APPENDS("E ");
				if (Result & COND_NE) APPENDS("NE ");
				if (Result & COND_C) APPENDS("C ");
				if (Result & COND_NC) APPENDS("NC ");
				if (Result & COND_Z) APPENDS("Z ");
				if (Result & COND_NZ) APPENDS("NZ ");
				if (Result & COND_P) APPENDS("P ");
				if (Result & COND_NP) APPENDS("NP ");
				if (Result & COND_PE) APPENDS("PE ");
				if (Result & COND_PO) APPENDS("PO ");
				if (Result & COND_O) APPENDS("O ");
				if (Result & COND_NO) APPENDS("NO ");
				if (Result & COND_U) APPENDS("U ");
				if (Result & COND_NU) APPENDS("NU ");
				if (Result & COND_S) APPENDS("S ");
				if (Result & COND_NS) APPENDS("NS ");
				if (Result & COND_D) APPENDS("D ");
				APPENDB('}');
			}

			if (X86Instruction->Opcode.FlagsChanged)
			{
				Result = X86Instruction->Opcode.FlagsChanged;

				if (Result & FLAG_SET_MASK)
				{
					APPENDS("SET:{ ");
					if (Result & FLAG_CF_SET) APPENDS("C ");
					if (Result & FLAG_DF_SET) APPENDS("D ");
					if (Result & FLAG_IF_SET) APPENDS("I ");
					APPENDB('}');
				}

				if (Result & FLAG_CLR_MASK)
				{
					APPENDS("CLR:{ ");
					if (Result & FLAG_SF_CLR) APPENDS("S ");
					if (Result & FLAG_ZF_CLR) APPENDS("Z ");
					if (Result & FLAG_AF_CLR) APPENDS("A ");
					if (Result & FLAG_CF_CLR) APPENDS("C ");
					if (Result & FLAG_DF_CLR) APPENDS("D ");
					if (Result & FLAG_IF_CLR) APPENDS("I ");
					if (Result & FLAG_OF_CLR) APPENDS("O ");
					if ((Result & FPU_ALL_CLR) == FPU_ALL_CLR)
					{
						APPENDS("FPU_ALL ");
					}
					else
					{
						if (Result & FPU_C0_CLR) APPENDS("FPU_C0 ");
						if (Result & FPU_C1_CLR) APPENDS("FPU_C1 ");
						if (Result & FPU_C2_CLR) APPENDS("FPU_C2 ");
						if (Result & FPU_C3_CLR) APPENDS("FPU_C3 ");
					}
					APPENDB('}');
				}

				if ((Result & FLAG_MOD_MASK) == FLAG_MOD_MASK)
				{
					APPENDS("MOD:{ ");
					if ((Result & FLAG_ALL_MOD) == FLAG_ALL_MOD)
					{
						APPENDS("FLAGS_ALL ");
					}
					else if ((Result & FLAG_COMMON_MOD) == FLAG_COMMON_MOD)
					{
						APPENDS("FLAGS_COMMON ");
					}
					else
					{
						if (Result & FLAG_OF_MOD) APPENDS("O ");
						if (Result & FLAG_SF_MOD) APPENDS("S ");
						if (Result & FLAG_ZF_MOD) APPENDS("Z ");
						if (Result & FLAG_AF_MOD) APPENDS("A ");
						if (Result & FLAG_PF_MOD) APPENDS("P ");
						if (Result & FLAG_CF_MOD) APPENDS("C ");
						if (Result & FLAG_DF_MOD) APPENDS("D ");
						if (Result & FLAG_IF_MOD) APPENDS("I ");
					}
					if ((Result & FPU_ALL_MOD) == FPU_ALL_MOD)
					{
						APPENDS("FPU_ALL ");
					}
					else
					{
						if (Result & FPU_C0_MOD) APPENDS("FPU_C0 ");
						if (Result & FPU_C1_MOD) APPENDS("FPU_C1 ");
						if (Result & FPU_C2_MOD) APPENDS("FPU_C2 ");
						if (Result & FPU_C3_MOD) APPENDS("FPU_C3 ");
					}
					APPENDB('}');
				}

				if (Result & FLAG_TOG_MASK)
				{
					APPENDS("TOG:{ ");
					if (Result & FLAG_CF_TOG) APPENDS("C ");
					APPENDB('}');
				}
			}
		}

		APPENDS("\n");
	}
	else
	{
		Instruction->String[0] = '\0';
	}

	if (!Instruction->Length || Instruction->Length > X86_MAX_INSTRUCTION_LEN)
	{
		if (!SuppressErrors) printf("[0x%08I64X] ERROR: maximum instruction length reached (\"%s\")\n", VIRTUAL_ADDRESS, X86Instruction->Opcode.Mnemonic);
		goto abort;
	}

	if (!Decode)
	{
		Disassembler->Stage3CountNoDecode++;
		return TRUE; // all work is done
	}

	//////////////////////////////////////////////////////////////////////
	// Detect particularly interesting intructions
	//////////////////////////////////////////////////////////////////////

	Operand1 = &Instruction->Operands[0];
	if (Instruction->Groups & ITYPE_EXEC)
	{
		// If it is a negative offset with a 1-byte or 2-byte offset, assume it is a loop
		if (Operand1->Type == OPTYPE_OFFSET && 
			Operand1->Length <= 2 && X86Instruction->Displacement < 0)
		{
			Instruction->CodeBranch.IsLoop = TRUE;
			Instruction->CodeBranch.Operand = Operand1;
		}

		if (!Instruction->AnomalyOccurred &&
			Operand1->TargetAddress >= (U64)Instruction->Address &&
			Operand1->TargetAddress < (U64)Instruction->Address + Instruction->Length)
		{
			if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: branch into the middle of an instruction\n", VIRTUAL_ADDRESS);
			Instruction->AnomalyOccurred = TRUE;
		}

		switch (Instruction->Type)
		{
			case ITYPE_BRANCH:
				Operand1->Flags |= OP_ADDRESS;
				assert(Instruction->OperandCount == 1);
				if (!(Operand1->Flags & (OP_GLOBAL|OP_FAR)))
				{
					assert(!X86Instruction->HasSelector);
					X86Instruction->Segment = SEG_CS;
				}
				
				if (Operand1->TargetAddress)
				{
					assert(!Instruction->CodeBranch.AddressOffset);
					Instruction->CodeBranch.Count = 1;
					Instruction->CodeBranch.Addresses[0] = Operand1->TargetAddress;
					Instruction->CodeBranch.Operand = Operand1;
				}
				// If there is both a base and index register, the Result will probably be too wrong
				// to even guess
				else if (X86Instruction->HasFullDisplacement && 
					 ((X86Instruction->HasBaseRegister && !X86Instruction->HasIndexRegister) ||
					 (!X86Instruction->HasBaseRegister && X86Instruction->HasIndexRegister)))
				{
					assert(Operand1->Length <= 0xFF);
					if (!X86Instruction->Scale)
					{
						if (Operand1->Length) X86Instruction->Scale = (U8)Operand1->Length;
						else X86Instruction->Scale = X86Instruction->OperandSize;
					}
					assert(Operand1->Length <= 0xFF);
					tmpScale = MAX(X86Instruction->Scale, Operand1->Length);

					assert(tmpScale <= 16);
					Instruction->CodeBranch.AddressOffset = (U8)tmpScale;
					for (i = 0; i < MAX_CODE_REFERENCE_COUNT; i++) Instruction->CodeBranch.Addresses[i] = (U64)X86Instruction->Displacement + (i * tmpScale);
					Instruction->CodeBranch.Count = i;
					Instruction->CodeBranch.IsIndirect = TRUE;
					Instruction->CodeBranch.Operand = Operand1;
				}
				break;

			case ITYPE_CALL:
				Instruction->Groups |= ITYPE_STACK;
				Instruction->CodeBranch.IsCall = TRUE;
				Operand1->Flags |= OP_ADDRESS;
				assert(Instruction->OperandCount == 1);
				if (!(Operand1->Flags & (OP_GLOBAL|OP_FAR)))
				{
					assert(!X86Instruction->HasSelector);
					X86Instruction->Segment = SEG_CS;
				}
								
				if (Operand1->TargetAddress)
				{
					assert(!Instruction->CodeBranch.AddressOffset);
					Instruction->CodeBranch.Count = 1;
					Instruction->CodeBranch.Addresses[0] = Operand1->TargetAddress;
					Instruction->CodeBranch.Operand = Operand1;
				}
				// If there is both a base and index register, the Result will probably be too wrong
				// to even guess
				else if (X86Instruction->HasFullDisplacement &&
					((X86Instruction->HasBaseRegister && !X86Instruction->HasIndexRegister) ||
					 (!X86Instruction->HasBaseRegister && X86Instruction->HasIndexRegister)))
				{
					//DISASM_OUTPUT(("[0x%08I64X] Scale %d, displacement 0x%08I64x\n", VIRTUAL_ADDRESS, X86Instruction->Scale, X86Instruction->Displacement));
					if (!X86Instruction->Scale)
					{
						assert(Operand1->Length <= 0xFF);
						if (Operand1->Length) X86Instruction->Scale = (U8)Operand1->Length;
						else X86Instruction->Scale = X86Instruction->OperandSize;
					}
					tmpScale = MAX(X86Instruction->Scale, Operand1->Length);

					assert(tmpScale <= 16);
					Instruction->CodeBranch.AddressOffset = (U8)tmpScale;
					assert(X86Instruction->Scale > 1);
					for (i = 0; i < MAX_CODE_REFERENCE_COUNT; i++) Instruction->CodeBranch.Addresses[i] = (U64)X86Instruction->Displacement + (i * tmpScale);
					Instruction->CodeBranch.Count = i;
					Instruction->CodeBranch.IsIndirect = TRUE;
					Instruction->CodeBranch.Operand = Operand1;
				}
				break;

			case ITYPE_BRANCHCC:
				assert(Instruction->OperandCount == 1);
				assert(Operand1->Flags & OP_ADDRESS);
				assert(Operand1->Type == OPTYPE_OFFSET);
				if (!(Operand1->Flags & (OP_GLOBAL|OP_FAR)))
				{
					assert(!X86Instruction->HasSelector);
					X86Instruction->Segment = SEG_CS;
				}

				if (Operand1->TargetAddress)
				{
					assert(!Instruction->CodeBranch.AddressOffset);
					Instruction->CodeBranch.Count = 2;
					Instruction->CodeBranch.Addresses[0] = Operand1->TargetAddress;
					Instruction->CodeBranch.Addresses[1] = (U64)Instruction->Address + Instruction->Length;
					Instruction->CodeBranch.Operand = Operand1;
				}
				break;

			case ITYPE_LOOPCC:
				Instruction->CodeBranch.IsLoop = TRUE;
				assert(Instruction->OperandCount == 1);
				assert(Operand1->Flags & OP_ADDRESS);
				assert(Operand1->Type == OPTYPE_OFFSET);
				assert(!(Operand1->Flags & (OP_GLOBAL|OP_FAR)));
				if (Operand1->TargetAddress)
				{
					assert(!Instruction->CodeBranch.AddressOffset);
					Instruction->CodeBranch.Count = 2;
					Instruction->CodeBranch.Addresses[0] = Operand1->TargetAddress;
					Instruction->CodeBranch.Addresses[1] = (U64)Instruction->Address + Instruction->Length;
					Instruction->CodeBranch.Operand = Operand1;
				}
				break;

			case ITYPE_RET:
				Instruction->Groups |= ITYPE_STACK;
				break;

			default:
				break; // do nothing
		}
	}
	else // possible data instruction
	{
		for (i = 0, Operand = Instruction->Operands; i < Instruction->OperandCount; i++, Operand++)
		{
			if (Operand->TargetAddress)
			{
				if (Operand->Flags & OP_DST)
				{
					assert(!Instruction->DataDst.Count);
					Instruction->DataDst.Count = 1;
					Instruction->DataDst.Addresses[0] = Operand->TargetAddress;
					Instruction->DataDst.DataSize = Operand->Length;
					Instruction->DataDst.Operand = Operand;
					DISASM_OUTPUT(("[0x%08I64X] Write of size %d to 0x%04I64X\n", VIRTUAL_ADDRESS, Operand->Length, Operand->TargetAddress));
				}
				if (Operand->Flags & OP_SRC)
				{
					assert(!Instruction->DataSrc.Count);
					Instruction->DataSrc.Count = 1;
					Instruction->DataSrc.Addresses[0] = Operand->TargetAddress;
					Instruction->DataSrc.DataSize = Operand->Length;
					Instruction->DataSrc.Operand = Operand;
					DISASM_OUTPUT(("[0x%08I64X] Read of size %d to 0x%04I64X\n", VIRTUAL_ADDRESS, Operand->Length, Operand->TargetAddress));
				}
			}

			// If there is both a base and index register, the Result will probably be too wrong
			// to even guess
			else if (Operand->Flags & OP_GLOBAL && 
				((X86Instruction->HasBaseRegister && !X86Instruction->HasIndexRegister) ||
				 (!X86Instruction->HasBaseRegister && X86Instruction->HasIndexRegister)))
			{
				DISASM_OUTPUT(("[0x%08I64X] Data reference (scale %d, size %d, displacement 0x%08I64x)\n", VIRTUAL_ADDRESS, X86Instruction->Scale, Operand->Length, X86Instruction->Displacement));
				if (!X86Instruction->Scale)
				{
					assert(Operand->Length <= 0xFF);
					if (Operand->Length) X86Instruction->Scale = (U8)Operand->Length;
					else X86Instruction->Scale = X86Instruction->OperandSize;
				}
				tmpScale = MAX(X86Instruction->Scale, Operand->Length);

				assert(X86Instruction->HasFullDisplacement);
				if (Operand->Flags & OP_DST)
				{
					assert(!Instruction->DataDst.Count);
					assert(tmpScale <= 16);
					Instruction->CodeBranch.AddressOffset = (U8)tmpScale;
					for (i = 0; i < MAX_DATA_REFERENCE_COUNT; i++) Instruction->DataDst.Addresses[i] = (U64)X86Instruction->Displacement + (i * tmpScale);
					Instruction->DataDst.Count = i;
					Instruction->DataDst.DataSize = Operand->Length;
					Instruction->DataDst.Operand = Operand;
				}					
				if (Operand->Flags & OP_SRC)
				{
					assert(!Instruction->DataSrc.Count);
					assert(tmpScale <= 16);
					Instruction->CodeBranch.AddressOffset = (U8)tmpScale;
					for (i = 0; i < MAX_DATA_REFERENCE_COUNT; i++) Instruction->DataSrc.Addresses[i] = (U64)X86Instruction->Displacement + (i * tmpScale);
					Instruction->DataSrc.Count = i;
					Instruction->DataSrc.DataSize = Operand->Length;
					Instruction->DataSrc.Operand = Operand;
				}
			}
		}
	}

	if (Instruction->Groups & ITYPE_STACK)
	{
		switch (Instruction->Type)
		{
			case ITYPE_PUSH:
				assert(Instruction->OperandCount == 1 && Operand1->Length);
				Instruction->StackChange = -Operand1->Length;
				SANITY_CHECK_ADDRESS_SIZE();
				break;

			case ITYPE_POP:
				assert(Instruction->OperandCount == 1 && Operand1->Length);
				Instruction->StackChange = Operand1->Length;
				SANITY_CHECK_ADDRESS_SIZE();
				break;

			case ITYPE_PUSHA:
				Instruction->StackChange = -(X86Instruction->OperandSize * 8); // xAX, xCX, xDX, xBX, xBP, xSP, xSI, xDI
				SANITY_CHECK_ADDRESS_SIZE();
				break;

			case ITYPE_POPA:
				Instruction->StackChange = X86Instruction->OperandSize * 8; // xDI, xSI, xSP, xBP, xBX, xDX, xCX, xAX
				SANITY_CHECK_ADDRESS_SIZE();
				break;

			case ITYPE_PUSHF:			
				Instruction->StackChange = -Operand1->Length;
				Instruction->NeedsEmulation = TRUE;
				SANITY_CHECK_ADDRESS_SIZE();
				break;

			case ITYPE_POPF:
				Instruction->StackChange = Operand1->Length;
				Instruction->NeedsEmulation = TRUE;
				SANITY_CHECK_ADDRESS_SIZE();
				break;

			case ITYPE_ENTER:
				if (!Instruction->AnomalyOccurred)
				{
					if (Instruction->Operands[1].Value_U64 & 3)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: ENTER has invalid operand 2\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					if (Instruction->Operands[2].Value_U64 & ~0x1F)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: ENTER has invalid operand 3\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
				}
				SANITY_CHECK_ADDRESS_SIZE();
				Instruction->Operands[2].Value_U64 &= 0x1F;

				// frame pointer + stack space
				i = Operand1->Length + (U32)Instruction->Operands[1].Value_U64;
				Instruction->StackChange = -((LONG)i);
				i = (U32)Instruction->Operands[2].Value_U64 * Operand1->Length;
				Instruction->StackChange -= i;
				break;

			case ITYPE_LEAVE:
				// This will do "mov esp, ebp; pop ebp" so the StackChange size is dynamic
				SANITY_CHECK_ADDRESS_SIZE();
				break;

			case ITYPE_CALL:
				Instruction->StackChange = -X86Instruction->OperandSize;
				SANITY_CHECK_ADDRESS_SIZE();
				break;

			case ITYPE_RET:
				Instruction->StackChange = X86Instruction->OperandSize;

				switch (Opcode)
				{
					case 0xC3: // ret with no args
						break;

					case 0xC2: // ret with 1 arg
						if (!Instruction->AnomalyOccurred && (Operand1->Value_U64 & 3))
						{
							if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: ret has invalid operand 1\n", VIRTUAL_ADDRESS);
							Instruction->AnomalyOccurred = TRUE;
						}
						Instruction->StackChange += (LONG)Operand1->Value_U64;
						break;

					case 0xCB: // far ret with no args
						Instruction->StackChange *= 2; // account for segment
						Instruction->StackChange += (LONG)Operand1->Value_U64;
						break;

					case 0xCA: // far ret with 1 arg
						if (!Instruction->AnomalyOccurred && (Operand1->Value_U64 & 3))
						{
							if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: retf has invalid operand 1\n", VIRTUAL_ADDRESS);
							Instruction->AnomalyOccurred = TRUE;
						}
						Instruction->StackChange *= 2; // account for segment
						Instruction->StackChange += (LONG)Operand1->Value_U64;
						break;
				}
				SANITY_CHECK_ADDRESS_SIZE();
				break;

			case ITYPE_ADD:
			case ITYPE_XCHGADD:
				if (Instruction->Operands[1].Value_S64) Instruction->StackChange = (LONG)(Instruction->Operands[1].Value_S64);
				break;
			case ITYPE_SUB:
				if (Instruction->Operands[1].Value_S64) Instruction->StackChange = (LONG)(-Instruction->Operands[1].Value_S64);
				break;
			case ITYPE_MOV:
			case ITYPE_AND:
				break;

			default:
				if (!Instruction->AnomalyOccurred)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Instruction \"%s\" is modifying the stack\n", VIRTUAL_ADDRESS, X86Opcode->Mnemonic);
					Instruction->AnomalyOccurred = TRUE;
				}
				break;
		}

		if (!Instruction->AnomalyOccurred &&
			((X86Instruction->OperandSize != 2 && (Instruction->StackChange & 3)) || (Instruction->StackChange & 1)))
		{
			if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: \"%s\" has invalid stack change 0x%02X\n", VIRTUAL_ADDRESS, X86Opcode->Mnemonic, Instruction->StackChange);
			Instruction->AnomalyOccurred = TRUE;
		}
	}

	if (Instruction->Groups & ITYPE_TRAPS)
	{
		switch (Instruction->Type)
		{
			case ITYPE_TRAP:
			case ITYPE_TRAPCC:
			case ITYPE_TRAPRET:
			case ITYPE_BOUNDS:
			case ITYPE_DEBUG:
			case ITYPE_TRACE:
			case ITYPE_INVALID:
			case ITYPE_OFLOW:
				Instruction->NeedsEmulation = TRUE;
				break;
			default:
				assert(0);
				break;
		}
	}

	if (Instruction->Groups & ITYPE_SYSTEM)
	{
		switch (Instruction->Type)
		{
			case ITYPE_CPUID:
			case ITYPE_SYSCALL:
			case ITYPE_SYSCALLRET:
				// This doesn't require privileges
				break;

			case ITYPE_HALT:
			case ITYPE_IN:
			case ITYPE_OUT:
			default:
				Instruction->NeedsEmulation = TRUE;
				break;
		}
	}

	Disassembler->Stage3CountWithDecode++;
	return TRUE;

abort:
	if (!SuppressErrors)
	{
#ifdef TEST_DISASM
		printf("Dump of 0x%04I64X:\n", VIRTUAL_ADDRESS);
		__try { DumpAsBytes(stdout, Instruction->Address, (ULONG_PTR)VIRTUAL_ADDRESS, 16, TRUE); }
		__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {}
#endif
		fflush(stdout);
	}
	return FALSE;
}

// Address = address to first byte after the opcode (e.g., first byte of ModR/M byte or
// immediate value
//
// Returns the address immediately following the operand (e.g., the next operand or the
// start of the next instruction
INTERNAL U8 *SetOperands(INSTRUCTION *Instruction, U8 *Address, U32 Flags)
{
	INSTRUCTION_OPERAND *Operand;
	U32 Index, OperandIndex;
	S64 Displacement = 0;
	U8 Register;
	U32 OperandFlags, OperandType, AddressMode, Segment;
	U8 Opcode;
	MODRM modrm;
	REX rex;
	REX_MODRM rex_modrm;
	X86_OPCODE *X86Opcode;
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;
	BOOL Decode = Flags & DISASM_DECODE;
	BOOL Disassemble = Flags & DISASM_DISASSEMBLE;
	BOOL SuppressErrors = Flags & DISASM_SUPPRESSERRORS;

	Opcode = Instruction->LastOpcode;
	X86Opcode = &X86Instruction->Opcode;

	// Setup Mod R/M byte
	if (X86Instruction->HasModRM)
	{
		SET_MODRM(X86Instruction->modrm, X86Instruction->modrm_b);
		modrm = X86Instruction->modrm;
		rex = X86Instruction->rex;
		SET_REX_MODRM(X86Instruction->rex_modrm, rex, modrm);
		rex_modrm = X86Instruction->rex_modrm;
		//DISASM_OUTPUT(("[0x%08I64X] ModRM = 0x%02X (mod=%d, reg=%d, rm=%d)\n", VIRTUAL_ADDRESS, X86Instruction->modrm_b, modrm.mod, rex_modrm.reg, rex_modrm.rm));
		INSTR_INC(1); // increment Instruction->Length and address
	}
	else
	{
		// initialize them to 0
		modrm = X86Instruction->modrm;
		rex = X86Instruction->rex;
		rex_modrm = X86Instruction->rex_modrm;
	}

	for (OperandIndex = 0; OperandIndex < Instruction->OperandCount; OperandIndex++)
	{
		Operand = &Instruction->Operands[OperandIndex];
		assert(!(Operand->Flags & 0x7F));
		
		OperandFlags = X86Opcode->OperandFlags[OperandIndex] & X86_OPFLAGS_MASK;
		OperandType = X86Opcode->OperandFlags[OperandIndex] & X86_OPTYPE_MASK;
		AddressMode = X86Opcode->OperandFlags[OperandIndex] & X86_AMODE_MASK;
		if (Decode && OperandIndex != 0) APPENDS(", ");

		switch (OperandType)
		{
			////////////////////////////////////////////////////////////
			// Special operand types with no associated addressing mode
			////////////////////////////////////////////////////////////

			case OPTYPE_0:
				if (!Decode) continue;
				Operand->Value_U64 = 0;
				Operand->Type = OPTYPE_IMM;
				//DISASM_OUTPUT(("[SetOperand] const 0\n"));
				if (Disassemble)
				{
					APPENDS("<0>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_1:
				if (!Decode) continue;
				Operand->Value_U64 = 1;
				Operand->Type = OPTYPE_IMM;
				//DISASM_OUTPUT(("[SetOperand] const 1\n"));
				if (Disassemble)
				{
					APPENDS("<1>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_FF:
				if (!Decode) continue;
				Operand->Value_U64 = 0xFF;
				Operand->Type = OPTYPE_IMM;
				//DISASM_OUTPUT(("[SetOperand] const 0xff\n"));
				if (Disassemble)
				{
					APPENDS("<0xFF>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_TSC:
				if (!Decode) continue;
				Operand->Length = 8;
				Operand->Type = OPTYPE_SPECIAL;
				//DISASM_OUTPUT(("[SetOperand] TSC\n"));
				if (Disassemble)
				{
					APPENDS("<TSC_MSR>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_CS_MSR:
				if (!Decode) continue;
				Operand->Length = 8;
				Operand->Type = OPTYPE_SPECIAL;
				//DISASM_OUTPUT(("[SetOperand] CS MSR\n"));
				if (Disassemble)
				{
					APPENDS("<CS_MSR>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_EIP_MSR:
				if (!Decode) continue;
				Operand->Length = 8;
				Operand->Type = OPTYPE_SPECIAL;
				//DISASM_OUTPUT(("[SetOperand] EIP MSR\n"));
				if (Disassemble)
				{
					APPENDS("<EIP_MSR>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_ESP_MSR:
				if (!Decode) continue;
				Operand->Length = 8;
				Operand->Type = OPTYPE_SPECIAL;
				//DISASM_OUTPUT(("[SetOperand] ESP MSR\n"));
				if (Disassemble)
				{
					APPENDS("<ESP_MSR>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_KERNELBASE_MSR:
				if (!Decode) continue;
				Operand->Length = 8;
				Operand->Type = OPTYPE_SPECIAL;
				//DISASM_OUTPUT(("[SetOperand] KernelBase MSR\n"));
				if (Disassemble)
				{
					APPENDS("<KRNLBASE_MSR>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_STAR_MSR:
				if (!Decode) continue;
				Operand->Length = 8;
				Operand->Type = OPTYPE_SPECIAL;
				//DISASM_OUTPUT(("[SetOperand] KernelBase MSR\n"));
				if (Disassemble)
				{
					APPENDS("<STAR_MSR>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_CSTAR_MSR:
				assert(!IS_AMD64());
				if (!Decode) continue;
				Operand->Length = 8;
				Operand->Type = OPTYPE_SPECIAL;
				//DISASM_OUTPUT(("[SetOperand] CSTAR MSR\n"));
				if (Disassemble)
				{
					APPENDS("<CSTAR_MSR>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_LSTAR_MSR:
				assert(IS_AMD64());
				if (!Decode) continue;
				Operand->Length = 8;
				Operand->Type = OPTYPE_SPECIAL;
				//DISASM_OUTPUT(("[SetOperand] LSTAR MSR\n"));
				if (Disassemble)
				{
					APPENDS("<LSTAR_MSR>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_FMASK_MSR:
				if (!Decode) continue;
				Operand->Length = 8;
				Operand->Type = OPTYPE_SPECIAL;
				//DISASM_OUTPUT(("[SetOperand] FMASK MSR\n"));
				if (Disassemble)
				{
					APPENDS("<FMASK_MSR>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OP_REG:
				if (!Decode) continue;
				// The reg field is included in the opcode
				Operand->Length = X86Instruction->OperandSize;
				Register = X86_GET_REG64(Opcode);
				switch (X86Instruction->OperandSize)
				{
					case 8:
						Operand->Register = AMD64_64BIT_OFFSET + Register;
						break;
					case 4:
						Operand->Register = X86_32BIT_OFFSET + Register;
						CHECK_AMD64_REG();
						break;
					case 2:
						Operand->Register = X86_16BIT_OFFSET + Register;
						CHECK_AMD64_REG();
						break;
					case 1:
						Operand->Register = X86_8BIT_OFFSET + Register;
						if (X86Instruction->rex_b) CHECK_AMD64_REG();
						break;
					default:
						assert(0);
						return NULL;
				}
				X86_SET_REG(Register);

				//DISASM_OUTPUT(("[SetOperand] OP_REG %s\n", X86_Registers[Operand->Register]));
				if (Disassemble)
				{
					APPENDB('<'); APPENDS(X86_Registers[Operand->Register]); APPENDB('>');
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_REG8:
				if (!Decode) continue;
				// The reg field is included in the opcode
				Operand->Length = 1;
				Register = X86_GET_REG64(Opcode);
				Operand->Register = X86_8BIT_OFFSET + Register;
				CHECK_AMD64_REG();
				X86_SET_REG(Register);

				//DISASM_OUTPUT(("[SetOperand] OP_REG %s\n", X86_Registers[Operand->Register]));
				if (Disassemble)
				{
					APPENDB('<'); APPENDS(X86_Registers[Operand->Register]); APPENDB('>');
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_REG_AL:
				if (!Decode) continue;
				Operand->Length = 1;
				Operand->Register = X86_REG_AL;
				X86_SET_REG(0);
				//DISASM_OUTPUT(("[SetOperand] reg AL\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_REG_CL:
				if (!Decode) continue;
				Operand->Length = 1;
				Operand->Register = X86_REG_CL;
				X86_SET_REG(0);
				//DISASM_OUTPUT(("[SetOperand] reg CL\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_REG_AH:
				if (!Decode) continue;
				Operand->Length = 1;
				Operand->Register = X86_REG_AH;
				X86_SET_REG(0);
				//DISASM_OUTPUT(("[SetOperand] reg AH\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_REG_AX:
				if (!Decode) continue;
				Operand->Length = 2;
				Operand->Register = X86_REG_AX;
				X86_SET_REG(0);
				//DISASM_OUTPUT(("[SetOperand] reg AX\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_REG_DX:
				if (!Decode) continue;
				Operand->Length = 2;
				Operand->Register = X86_REG_DX;
				X86_SET_REG(0);
				//DISASM_OUTPUT(("[SetOperand] reg DX\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_REG_ECX:
				if (!Decode) continue;
				Operand->Length = 4;
				Operand->Register = X86_REG_ECX;
				X86_SET_REG(0);
				//DISASM_OUTPUT(("[SetOperand] reg ECX\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_REG_xBP:
				if (!Decode) continue;
				Operand->Length = X86Instruction->OperandSize; 
				switch (X86Instruction->OperandSize)
				{
					case 8: Operand->Register = AMD64_REG_RBP; break;
					case 4: Operand->Register = X86_REG_EBP; break;
					case 2: Operand->Register = X86_REG_BP; break;
					default: assert(0); return NULL;
				}
				X86_SET_REG(0);
				//DISASM_OUTPUT(("[SetOperand] xAX_BIG (size = %d)\n", Operand->Length));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_REG_xAX_BIG:
				if (!Decode) continue;
				Operand->Length = X86Instruction->OperandSize; 
				switch (X86Instruction->OperandSize)
				{
					case 8: Operand->Register = AMD64_REG_RAX; break;
					case 4: Operand->Register = X86_REG_EAX; break;
					case 2: Operand->Register = X86_REG_AX; break;
					default: assert(0); return NULL;
				}
				X86_SET_REG(0);
				//DISASM_OUTPUT(("[SetOperand] xAX_BIG (size = %d)\n", Operand->Length));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_REG_xAX_SMALL:
				if (!Decode) continue;
				Operand->Length = X86Instruction->OperandSize >> 1; 
				switch (X86Instruction->OperandSize)
				{
					case 8: Operand->Register = X86_REG_EAX; break;
					case 4: Operand->Register = X86_REG_AX; break;
					case 2: Operand->Register = X86_REG_AL; break;
					default: assert(0); return NULL;
				}
				X86_SET_REG(0);
				//DISASM_OUTPUT(("[SetOperand] xAX_SMALL (size = %d)\n", Operand->Length));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_xCX_HI_xBX_LO:
				if (!Decode) continue;
				Operand->Length = X86Instruction->OperandSize << 1; 
				if (Disassemble)
				{
					switch (X86Instruction->OperandSize)
					{
						case 8: APPENDS("<RCX:RBX>"); break;
						case 4: APPENDS("<ECX:EBX>"); break;
						case 2: APPENDS("<CX:BX>"); break;
						default: assert(0); return NULL;
					}
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] xCX_BIG:xBX_BIG (size = %d)\n", Operand->Length));
				continue;
			case OPTYPE_xDX_HI_xAX_LO:
				if (!Decode) continue;
				Operand->Length = X86Instruction->OperandSize << 1; 
				if (Disassemble)
				{
					switch (X86Instruction->OperandSize)
					{
						case 8: APPENDS("<RDX:RAX>"); break;
						case 4: APPENDS("<EDX:EAX>"); break;
						case 2: APPENDS("<DX:AX>"); break;
						default: assert(0); return NULL;
					}
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] xDX_BIG:xAX_BIG (size = %d)\n", Operand->Length));
				continue;

			case OPTYPE_EDX_HI_EAX_LO:
				if (!Decode) continue;
				Operand->Length = 8;
				//DISASM_OUTPUT(("[SetOperand] EDX:EAX\n"));
				if (Disassemble)
				{
					APPENDS("<EDX:EAX>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_EDX_ECX_EBX_EAX:
				Operand->Length = 32;
				//DISASM_OUTPUT(("[SetOperand] EDX:ECX:EBX:EAX\n"));
				if (Disassemble)
				{
					APPENDS("<EDX:ECX:EBX:EAX>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_FLAGS:
				if (!Decode) continue;
				Operand->Length = 2;
				Operand->Flags |= OP_REG;
				Operand->Register = X86_REG_FLAGS;
				//DISASM_OUTPUT(("[SetOperand] reg FLAGS\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_xFLAGS:
				if (!Decode) continue;
				Operand->Length = X86Instruction->OperandSize; 
				Operand->Flags |= OP_REG;
				switch (X86Instruction->OperandSize)
				{
					case 8: Operand->Register = AMD64_REG_RFLAGS; break;
					case 4: Operand->Register = X86_REG_EFLAGS; break;
					case 2: Operand->Register = X86_REG_FLAGS; break;
					default: assert(0); return NULL;
				}
				//DISASM_OUTPUT(("[SetOperand] reg xFLAGS (size = %d)\n", Operand->Length));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_CS:
				if (!Decode) continue;
				if (Instruction->Type != ITYPE_PUSH && Instruction->Type != ITYPE_POP) Operand->Length = 2;
				else Operand->Length = X86Instruction->OperandSize;
				Operand->Register = X86_SEG_CS;
				Operand->Flags |= OP_REG;
				//DISASM_OUTPUT(("[SetOperand] seg CS\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_DS:
				if (!Decode) continue;
				if (Instruction->Type != ITYPE_PUSH && Instruction->Type != ITYPE_POP) Operand->Length = 2;
				else Operand->Length = X86Instruction->OperandSize;
				Operand->Register = X86_SEG_DS;
				Operand->Flags |= OP_REG;
				//DISASM_OUTPUT(("[SetOperand] seg DS\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_ES:
				if (!Decode) continue;
				if (Instruction->Type != ITYPE_PUSH && Instruction->Type != ITYPE_POP) Operand->Length = 2;
				else Operand->Length = X86Instruction->OperandSize;
				Operand->Register = X86_SEG_ES;
				Operand->Flags |= OP_REG;
				//DISASM_OUTPUT(("[SetOperand] seg ES\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_FS:
				if (!Decode) continue;
				if (Instruction->Type != ITYPE_PUSH && Instruction->Type != ITYPE_POP) Operand->Length = 2;
				else Operand->Length = X86Instruction->OperandSize;
				Operand->Register = X86_SEG_FS;
				Operand->Flags |= OP_REG;
				//DISASM_OUTPUT(("[SetOperand] seg FS\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_GS:
				if (!Decode) continue;
				if (Instruction->Type != ITYPE_PUSH && Instruction->Type != ITYPE_POP) Operand->Length = 2;
				else Operand->Length = X86Instruction->OperandSize;
				Operand->Register = X86_SEG_GS;
				Operand->Flags |= OP_REG;
				//DISASM_OUTPUT(("[SetOperand] seg GS\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_SS:
				if (!Decode) continue;
				if (Instruction->Type != ITYPE_PUSH && Instruction->Type != ITYPE_POP) Operand->Length = 2;
				else Operand->Length = X86Instruction->OperandSize;
				Operand->Register = X86_SEG_SS;
				Operand->Flags |= OP_REG;
				//DISASM_OUTPUT(("[SetOperand] seg SS\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_CR0:
				if (!Decode) continue;
				Operand->Length = X86Instruction->OperandSize;
				Operand->Register = X86_REG_CR0;
				Operand->Flags |= OP_REG;
				//DISASM_OUTPUT(("[SetOperand] reg CR0\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_STx:
				if (!Decode) continue;
				Operand->Length = 10;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Flags |= OP_REG;
				Register = X86_GET_REG(X86Instruction->modrm_b);
				Operand->Register = X86_FPU_OFFSET + Register;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_STx: reg st(%d)\n", Register));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_ST0:
				if (!Decode) continue;
				Operand->Length = 10;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Flags |= OP_REG;
				Operand->Register = X86_REG_ST0;
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_ST1:
				if (!Decode) continue;
				Operand->Length = 10;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Flags |= OP_REG;
				Operand->Register = X86_REG_ST1;
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "<%s>", X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_FPU_STATUS:
				if (!Decode) continue;
				Operand->Length = 2;
				if (Disassemble)
				{
					APPENDS("<FPUSTAT>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_FPU_CONTROL:
				if (!Decode) continue;
				Operand->Length = 2;
				if (Disassemble)
				{
					APPENDS("<FPUCTRL>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_FPU_TAG:
				if (!Decode) continue;
				Operand->Length = 2;
				if (Disassemble)
				{
					APPENDS("<FPUTAG>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			case OPTYPE_FLDZ:
				if (!Decode) continue;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Length = 10;
				if (Disassemble)
				{
					APPENDS("<0.0>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_FLD1:
				if (!Decode) continue;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Length = 10;
				if (Disassemble)
				{
					APPENDS("<1.0>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_FLDPI:
				if (!Decode) continue;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Length = 10;
				if (Disassemble)
				{
					APPENDS("<pi>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_FLDL2T:
				if (!Decode) continue;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Length = 10;
				if (Disassemble)
				{
					APPENDS("<log_2 10>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_FLDL2E:
				if (!Decode) continue;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Length = 10;
				if (Disassemble)
				{
					APPENDS("<log_2 e>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_FLDLG2:
				if (!Decode) continue;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Length = 10;
				if (Disassemble)
				{
					APPENDS("<log_10 2>");
					X86_WRITE_OPFLAGS();
				}
				continue;
			case OPTYPE_FLDLN2:
				if (!Decode) continue;
				Operand->Type = OPTYPE_FLOAT;
				Operand->Length = 10;
				if (Disassemble)
				{
					APPENDS("<ln 2>");
					X86_WRITE_OPFLAGS();
				}
				continue;

			////////////////////////////////////////////////////////////
			// Fixed sizes regardless of operand size
			////////////////////////////////////////////////////////////

			case OPTYPE_b: // byte regardless of operand size
				Operand->Length = 1;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_b (size 1, signed %d)\n", ((OperandFlags & OP_SIGNED) != 0)));
				break;

			case OPTYPE_w: // word regardless of operand size
				Operand->Length = 2;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_w (size 2)\n"));
				break;

			case OPTYPE_d: // dword regardless of operand size
				Operand->Length = 4;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_d (size 4)\n"));
				break;

			case OPTYPE_q: // qword regardless of operand size
				Operand->Length = 8;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_q (size 8)\n"));
				break;

			case OPTYPE_o: // oword regardless of operand size
				Operand->Length = 16;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_o (size 16)\n"));
				break;

			case OPTYPE_dt: // 6-byte or 10-byte pseudo descriptor (sgdt, lgdt, sidt, lidt)
				if (IS_AMD64()) Operand->Length = 10;
				else Operand->Length = 6;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_dt (%d bytes)\n", Operand->Length));
				break;

			case OPTYPE_cpu:
				if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Undocumented loadall instruction?\n", VIRTUAL_ADDRESS);
				Instruction->AnomalyOccurred = TRUE;
				Operand->Length = 204;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_cpu (size 204)\n"));
				break;

			////////////////////////////////////////////////////////////
			// Sizes depending on the operand size
			////////////////////////////////////////////////////////////

			case OPTYPE_z: // word if operand size is 16 bits and dword otherwise
				switch (X86Instruction->OperandSize)
				{
					case 8: case 4: Operand->Length = 4; break;
					case 2: Operand->Length = 2; break;
					default: assert(0); return NULL;
				}
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_z (length %d)\n", Operand->Length));
				break;

			case OPTYPE_v: // word, dword, or qword
				Operand->Length = X86Instruction->OperandSize;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_v (size %d, signed = %d)\n", Operand->Length, ((OperandFlags & OP_SIGNED) != 0)));
				break;

			case OPTYPE_a: // two word or dword operands in memory (used only by bound)
				assert(Instruction->OpcodeBytes[0] == X86_BOUND);
				switch (X86Instruction->OperandSize)
				{
					case 8: case 4: Operand->Length = 8; break;
					case 2: Operand->Length = 4; break;
					default: assert(0); return NULL;
				}
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_a (size %d)\n", Operand->Length));
				break;

			case OPTYPE_p: // 32-bit or 48-bit pointer depending on operand size
				if (!Instruction->AnomalyOccurred && X86Instruction->HasSegmentOverridePrefix)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Segment override used when segment is explicit\n", VIRTUAL_ADDRESS);
					Instruction->AnomalyOccurred = TRUE;
				}
				switch (X86Instruction->OperandSize)
				{
					case 8: case 4: Operand->Length = 6; break;
					case 2: Operand->Length = 4; break;
					default: assert(0); return NULL;
				}
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_p (length %d)\n", Operand->Length));
				break;

			case OPTYPE_dq: // dword or qword
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_dq (size 4 or 8)\n"));
				switch (X86Instruction->OperandSize)
				{
					case 8: Operand->Length = 8; break;
					case 4: case 2: Operand->Length = 4; break;
					default: assert(0); return NULL;
				}
				break;

			case OPTYPE_mw: // a word if the destination operand is memory
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_mw (size 0)\n"));
				assert(X86Instruction->HasModRM);		
				if (modrm.mod == 3) Operand->Length = X86Instruction->OperandSize; // using register
				else Operand->Length = 2; // using memory
				break;

			case OPTYPE_lea:
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_lea (size 0)\n"));
				assert(OperandIndex == 1);
				Operand->Length = Instruction->Operands[0].Length;
				break;

			////////////////////////////////////////////////////////////
			// FPU types
			////////////////////////////////////////////////////////////

			case OPTYPE_ps: // packed single real
				Operand->Length = 4;
				Operand->Type = OPTYPE_FLOAT;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_ps (packed single real)\n"));
				break;
			case OPTYPE_pd: // packed double real
				Operand->Length = 8;
				Operand->Type = OPTYPE_FLOAT;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_pd (packed double real)\n"));
				break;
			case OPTYPE_pb: // packed BCD
				Operand->Length = 10;
				Operand->Type = OPTYPE_BCD;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_pb (packed BCD)\n"));
				break;
			case OPTYPE_ss: // scalar single real
				Operand->Length = 4;
				Operand->Type = OPTYPE_FLOAT;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_ss (single real)\n"));
				break;
			case OPTYPE_sd: // scalar double real
				Operand->Length = 8;
				Operand->Type = OPTYPE_FLOAT;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_sd (double real)\n"));
				break;
			case OPTYPE_se: // extended real
				Operand->Length = 10;
				Operand->Type = OPTYPE_FLOAT;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_se (extended real)\n"));
				break;

			case OPTYPE_fev: // FPU environment (28 bytes in 32-bit modes, 14 bytes in 16-bit real mode)
				switch (X86Instruction->OperandSize)
				{
					case 8: case 4: Operand->Length = 28; break;
					case 2: Operand->Length = 14; break;
					default: assert(0); return NULL;
				}
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_fev (FPU environment, length %d)\n", Operand->Length));
				break;

			case OPTYPE_fst1: // FPU state (108 bytes in 32-bit modes, 94 bytes in 16-bit real mode)
				switch (X86Instruction->OperandSize)
				{
					case 8: case 4: Operand->Length = 108; break;
					case 2: Operand->Length = 94; break;
					default: assert(0); return NULL;
				}
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_fst1 (FPU state, length %d)\n", Operand->Length));
				break;

			case OPTYPE_fst2: // 512 bytes for FPU state (FPU + MMX + XXM + MXCSR)
				Operand->Length = 512;
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_fst2 (FPU + MMX + XXM + MXCSR state, length 512)\n"));
				break;

			case OPTYPE_sso:
				if (modrm.mod == 3) // from register
				{
					Operand->Length = 16;
				}
				else // from memory
				{
					Operand->Length = 4;
					Operand->Type = OPTYPE_FLOAT;
				}
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_sso (single real or oword)\n"));
				break;

			case OPTYPE_sdo:
				if (modrm.mod == 3) // from register
				{
					Operand->Length = 16;
				}
				else // from memory
				{
					Operand->Length = 8;
					Operand->Type = OPTYPE_FLOAT;
				}
				//DISASM_OUTPUT(("[SetOperand] OPTYPE_sso (double real or oword)\n"));
				break;

			default:
				assert(0);
				return NULL;
		}

		switch (AddressMode)
		{
			////////////////////////////////////////////////////////////
			// Special types
			////////////////////////////////////////////////////////////

			case AMODE_xlat: // DS:[EBX+AL]
				if (!Decode) continue;
				assert(Operand->Length == 1);
				Operand->Flags |= OP_ADDRESS | OP_REG;
				Operand->Type = OPTYPE_STRING;
				
				switch (X86Instruction->AddressSize)
				{
					case 8: Operand->Register = AMD64_REG_RBX; break;
					case 4: Operand->Register = X86_REG_EBX; break;
					case 2: Operand->Register = X86_REG_BX; break;
					default: assert(0); return NULL;
				}
				X86_SET_ADDR();
				X86Instruction->Scale = 1;
				X86Instruction->BaseRegister = Operand->Register;
				X86Instruction->HasBaseRegister = TRUE;
				X86Instruction->IndexRegister = X86_REG_AL;
				X86Instruction->HasIndexRegister = TRUE;

				//DISASM_OUTPUT(("[SetOperand] AMODE_xlat (DS:[EBX+AL])\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "%s:[%s]", 
						Segments[X86Instruction->Segment], X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			////////////////////////////////////////////////////////////
			// Without mod R/M byte
			////////////////////////////////////////////////////////////

			case AMODE_I: // immediate value
				if (Decode)
				{
					Operand->Type = OPTYPE_IMM;
					switch (Operand->Length)
					{
						case 8:
							if (OperandFlags & OP_SIGNED) Operand->Value_S64 = (S64)*((S64 *)Address);
							else Operand->Value_U64 = (U64)*((U64 *)Address);
							break;
						case 4:
							if (!(OperandFlags & OP_SIGNED) && OperandIndex == 1 && 
								(Instruction->Operands[0].Flags & (OP_REG|OP_ADDRESS)) &&
								Instruction->Operands[0].Length == 8)
							{
								// For some opcodes the second operand is a sign-extended imm32 value
								assert(X86Instruction->OperandSize == 8);
								switch (Instruction->Type)
								{
									case ITYPE_AND:
									case ITYPE_ADD:
									case ITYPE_XCHGADD:
									case ITYPE_CMP:
									case ITYPE_MOV:
									case ITYPE_SUB:
									case ITYPE_TEST:
									case ITYPE_OR:
									case ITYPE_XOR:
										assert(OperandIndex == 1);
										Operand->Value_S64 = (S64)*((S32 *)Address);
										break;
									default:
										assert(0);
										if (OperandFlags & OP_SIGNED) Operand->Value_S64 = (S64)*((S32 *)Address);
										else Operand->Value_U64 = (U64)*((U32 *)Address);
										break;
								}
							}
							else
							{
								if (OperandFlags & OP_SIGNED) Operand->Value_S64 = (S64)*((S32 *)Address);
								else Operand->Value_U64 = (U64)*((U32 *)Address);
							}
							break;
						case 2:
							if (OperandFlags & OP_SIGNED) Operand->Value_S64 = (S64)*((S16 *)Address);
							else Operand->Value_U64 = (U64)*((U16 *)Address);
							break;
						case 1:
							if (OperandFlags & OP_SIGNED) Operand->Value_S64 = (S64)*((S8 *)Address);
							else Operand->Value_U64 = (U64)*((U8 *)Address);
							break;
						default:
							assert(0);
							return NULL;
					}
				}
				INSTR_INC(Operand->Length); // increment Instruction->Length and address
				assert(X86Instruction->OperandSize >= Operand->Length);
				if (Instruction->Type == ITYPE_PUSH) Operand->Length = X86Instruction->OperandSize;

				//DISASM_OUTPUT(("[SetOperand] AMODE_I (immediate data)\n"));
				if (Disassemble)
				{
					X86_WRITE_IMMEDIATE();
					X86_WRITE_OPFLAGS();
				}
				continue;

			case AMODE_J: // IP-relative jump offset
				SANITY_CHECK_ADDRESS_SIZE();
				if (Decode)
				{
					Operand->Flags |= OP_IPREL | OP_SIGNED | OP_REG | OP_ADDRESS;
					Operand->Type = OPTYPE_OFFSET;
					switch (X86Instruction->OperandSize)
					{
						case 8: Operand->Register = AMD64_REG_RIP; break;
						case 4: Operand->Register = X86_REG_EIP; break;
						case 2: Operand->Register = X86_REG_IP; break;
						default: assert(0); return NULL;
					}
					switch (Operand->Length)
					{
						case 8: X86Instruction->Displacement = *((S64 *)Address); break;
						case 4: X86Instruction->Displacement = (S64)*((S32 *)Address); break;
						case 2: X86Instruction->Displacement = (S64)*((S16 *)Address); break;
						case 1: X86Instruction->Displacement = (S64)*((S8 *)Address); break;
						default: assert(0); return NULL;
					}					

					Operand->Value_S64 = X86Instruction->Displacement;
					X86Instruction->Relative = TRUE;

					if ((Operand->Flags & OP_COND) && !X86Instruction->Displacement)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: Both conditions of branch go to same address\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
				}

				INSTR_INC(Operand->Length); // increment Instruction->Length and address
				if (!Decode) continue;

				assert((Operand->Flags & OP_EXEC) && (Instruction->Groups & ITYPE_EXEC));
				Operand->TargetAddress = ApplyDisplacement((U64)Address, Instruction);
				X86Instruction->Relative = TRUE; 
				X86_SET_ADDR();
				SANITY_CHECK_SEGMENT_OVERRIDE();
				X86Instruction->HasSegmentOverridePrefix = FALSE;
				X86Instruction->Segment = SEG_CS;
				X86Instruction->BaseRegister = Operand->Register;
				X86Instruction->HasBaseRegister = TRUE;
				assert(Instruction->OperandCount == 1);
				//DISASM_OUTPUT(("[SetOperand] AMODE_J (branch with relative offset)\n"));
				if (Disassemble)
				{
					X86_WRITE_IP_OFFSET(Operand);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case AMODE_O: // word/dword offset
				Operand->Type = OPTYPE_OFFSET;
				Operand->Flags |= OP_ADDRESS;
				SANITY_CHECK_OPERAND_SIZE();
				switch (X86Instruction->AddressSize)
				{
					case 8:
						if (Operand->Flags & OP_SIGNED) X86Instruction->Displacement = *((S64 *)Address);
						else X86Instruction->Displacement = (S64)*((U64 *)Address);
						break;
					case 4:
						if (Operand->Flags & OP_SIGNED) X86Instruction->Displacement = (S64)*((S32 *)Address);
						else X86Instruction->Displacement = (S64)*((U32 *)Address);
						break;
					case 2:
						if (Operand->Flags & OP_SIGNED) X86Instruction->Displacement = (S64)*((S16 *)Address);
						else X86Instruction->Displacement = (S64)*((U16 *)Address);
						break;
					default:
						assert(0);
						return FALSE;
				}

				INSTR_INC(X86Instruction->AddressSize); // increment Instruction->Length and address
				if (!Decode) continue;

				X86Instruction->HasFullDisplacement = TRUE;
				X86_SET_ADDR();
				X86_SET_TARGET();
				assert(X86Instruction->Segment == SEG_DS || X86Instruction->HasSegmentOverridePrefix);
				//DISASM_OUTPUT(("[SetOperand] AMODE_O (offset)\n"));
				if (Disassemble)
				{
					X86_WRITE_OFFSET(Operand);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case AMODE_A: // absolute address
				Operand->Flags |= OP_ADDRESS | OP_FAR;
				SANITY_CHECK_ADDRESS_SIZE();
				SANITY_CHECK_SEGMENT_OVERRIDE();
				X86Instruction->HasSelector = TRUE;
				X86Instruction->HasSegmentOverridePrefix = FALSE;
				switch (Operand->Length)
				{
					case 6:
						X86Instruction->Segment = *((U16 *)Address); INSTR_INC(2);
						X86Instruction->Displacement = (S64)*((S32 *)Address); INSTR_INC(4);
						break;
					case 4:
						X86Instruction->Segment = *((U16 *)Address); INSTR_INC(2);
						X86Instruction->Displacement = (S64)*((S16 *)Address); INSTR_INC(2);
						break;
					default:
						assert(0);
						return FALSE;
				}
				if (!Decode) continue;
				X86Instruction->HasFullDisplacement = TRUE;
				X86_SET_ADDR();
				X86_SET_TARGET();
				//DISASM_OUTPUT(("[SetOperand] AMODE_A (absolute address)\n"));
				if (Disassemble)
				{
					X86_WRITE_OFFSET(Operand);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case AMODE_X: // DS:[ESI]
				if (!Decode) continue;
				Operand->Flags |= OP_ADDRESS | OP_REG;
				Operand->Type = OPTYPE_STRING;
				switch (X86Instruction->AddressSize)
				{
					case 8: Operand->Register = AMD64_REG_RSI; break;
					case 4: Operand->Register = X86_REG_ESI; break;
					case 2: Operand->Register = X86_REG_SI; break;
					default: assert(0); return NULL;
				}

				X86Instruction->BaseRegister = Operand->Register;
				X86Instruction->HasBaseRegister = TRUE;
				X86_SET_ADDR();
				if (!X86Instruction->HasSegmentOverridePrefix) X86Instruction->Segment = SEG_DS;

				//DISASM_OUTPUT(("[SetOperand] AMODE_X (addressing via DS:[ESI])\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "%s:[%s]", 
						Segments[X86Instruction->Segment], X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;

			case AMODE_Y: // ES:[EDI]
				if (!Decode) continue;
				Operand->Flags |= OP_ADDRESS | OP_REG;
				Operand->Type = OPTYPE_STRING;
				switch (X86Instruction->AddressSize)
				{
					case 8: Operand->Register = AMD64_REG_RDI; break;
					case 4: Operand->Register = X86_REG_EDI; break;
					case 2: Operand->Register = X86_REG_DI; break;
					default: assert(0); return NULL;
				}

				X86Instruction->BaseRegister = Operand->Register;
				X86Instruction->HasBaseRegister = TRUE;
				X86_SET_ADDR();
				if (X86Instruction->HasSegmentOverridePrefix)
				{
					if (!Instruction->AnomalyOccurred)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ANOMALY: segment override used with AMODE_Y\n", VIRTUAL_ADDRESS);
						Instruction->AnomalyOccurred = TRUE;
					}
					Segment = X86Instruction->DstSegment = SEG_ES;
					X86Instruction->HasDstSegment = TRUE;
				}
				else
				{
					Segment = X86Instruction->Segment = SEG_ES;
				}

				//DISASM_OUTPUT(("[SetOperand] AMODE_Y (addressing via ES:[EDI])\n"));
				if (Disassemble)
				{
					APPEND(OPCSTR, SIZE_LEFT, "%s:[%s]", 
						Segments[Segment], X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				continue;
			
			////////////////////////////////////////////////////////////
			// Mod R/M byte with only registers
			// Handle that case here since it is straightforward
			////////////////////////////////////////////////////////////

			case AMODE_PR: // modrm.rm = mmx register and modrm.mod = 11
				assert(X86Instruction->HasModRM);
				if (modrm.mod != 3)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: mod != 3 for AMODE_PR (\"%s\")\n", VIRTUAL_ADDRESS, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				else if (rex_modrm.rm > 7)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: invalid mmx register %d for AMODE_PR (\"%s\")\n", VIRTUAL_ADDRESS, rex_modrm.rm, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				else if (X86Instruction->OperandSize == 2)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: AMODE_PR illegal in 16-bit mode (\"%s\")\n", VIRTUAL_ADDRESS, rex_modrm.rm, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				if (!Decode) continue;

				Operand->Flags |= OP_REG;
				Operand->Register = X86_MMX_OFFSET + rex_modrm.rm;
				X86_SET_REG(0);

				if (Disassemble)
				{
					assert(X86_Registers[Operand->Register]);
					APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_PR (MMX register)\n"));
				continue;

			case AMODE_VR: // modrm.rm = xmm register and modrm.mod = 11
				assert(X86Instruction->HasModRM);
				if (modrm.mod != 3)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: mod != 3 for AMODE_VR (\"%s\")\n", VIRTUAL_ADDRESS, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				else if (X86Instruction->OperandSize == 2)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: AMODE_VR illegal in 16-bit mode (\"%s\")\n", VIRTUAL_ADDRESS, rex_modrm.rm, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				if (!Decode) continue;

				Operand->Flags |= OP_REG;
				Operand->Register = X86_XMM_OFFSET + rex_modrm.rm;
				X86_SET_REG(0);

				if (Disassemble)
				{
					APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_VR (XMM register)\n"));
				continue;

			case AMODE_P: // modrm.reg = mmx register
				assert(X86Instruction->HasModRM);
				if (rex_modrm.reg > 7)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: invalid mmx register %d for AMODE_P (\"%s\")\n", VIRTUAL_ADDRESS, rex_modrm.reg, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				else if (X86Instruction->OperandSize == 2)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: AMODE_P illegal in 16-bit mode (\"%s\")\n", VIRTUAL_ADDRESS, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				if (!Decode) continue;

				Operand->Flags |= OP_REG;
				Operand->Register = X86_MMX_OFFSET + rex_modrm.reg;
				X86_SET_REG(0);

				if (Disassemble)
				{
					APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_P (MMX register)\n"));
				continue;

			case AMODE_V: // modrm.reg = xmm register
				assert(X86Instruction->HasModRM);
				if (X86Instruction->OperandSize == 2)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: AMODE_P illegal in 16-bit mode (\"%s\")\n", VIRTUAL_ADDRESS, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				if (!Decode) continue;

				Operand->Flags |= OP_REG;
				Operand->Register = X86_XMM_OFFSET + rex_modrm.reg; break;
				X86_SET_REG(0);

				if (Disassemble)
				{
					APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_V (XMM register)\n"));
				continue;

			case AMODE_R: // modrm.rm is general register and modrm.mod = 11
				assert(X86Instruction->HasModRM);
				if (modrm.mod != 3)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: mod != 3 for AMODE_R (\"%s\")\n", VIRTUAL_ADDRESS, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				if (!Decode) continue;
				Operand->Flags |= OP_REG;
				switch (Operand->Length)
				{
					case 8: Operand->Register = AMD64_64BIT_OFFSET + rex_modrm.rm; break;
					case 4: Operand->Register = X86_32BIT_OFFSET, rex_modrm.rm; CHECK_AMD64_REG(); break;
					case 2: Operand->Register = X86_16BIT_OFFSET, rex_modrm.rm; CHECK_AMD64_REG(); break;
					case 1: Operand->Register = X86_8BIT_OFFSET, rex_modrm.rm; if (X86Instruction->rex_b) CHECK_AMD64_REG(); break;
					default: assert(0); return NULL;
				}
				X86_SET_REG(rex_modrm.rm);
				if (Disassemble)
				{
					APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_R (general register)\n"));
				continue;

			case AMODE_G: // modrm.reg = general register
				assert(X86Instruction->HasModRM);
				if (!Decode) continue;
				Operand->Flags |= OP_REG;
				switch (Operand->Length)
				{
					case 8: Operand->Register = AMD64_64BIT_OFFSET + rex_modrm.reg; break;
					case 4: Operand->Register = X86_32BIT_OFFSET + rex_modrm.reg; CHECK_AMD64_REG(); break;
					case 2: Operand->Register = X86_16BIT_OFFSET + rex_modrm.reg; CHECK_AMD64_REG(); break;
					case 1: Operand->Register = X86_8BIT_OFFSET + rex_modrm.reg; if (X86Instruction->rex_b) CHECK_AMD64_REG(); break;
					default: assert(0); return NULL;
				}
				X86_SET_REG(rex_modrm.reg);
				if (Disassemble)
				{
					APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_G (general register)\n"));
				continue;
			
			case AMODE_S: // modrm.reg = segment register
				assert(X86Instruction->HasModRM);
				if (!Decode) continue;
				Operand->Flags |= OP_REG;
				switch (X86Instruction->OperandSize)
				{
					case 8:
					case 4:
					case 2:
						if (rex_modrm.reg <= 5) Operand->Register = X86_SEGMENT_OFFSET + rex_modrm.reg;
						break;
					default:
						assert(0);
						return NULL;
				}

				X86_SET_REG(0);
				if (Disassemble)
				{
					if (rex_modrm.reg > 5) APPEND(OPCSTR, SIZE_LEFT, "seg_%02X", rex_modrm.reg);
					else APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_S (segment register)\n"));
				continue;

			case AMODE_T: // modrm.reg = test register
				assert(X86Instruction->HasModRM);
				if (!Decode) continue;
				Instruction->Groups |= ITYPE_SYSTEM;
				Instruction->NeedsEmulation = TRUE;
				Operand->Flags |= OP_REG;
				switch (X86Instruction->OperandSize)
				{
					case 8:
					case 4:
					case 2:
						Operand->Register = X86_TEST_OFFSET + rex_modrm.reg;
						break;
					default:
						assert(0);
						return NULL;
				}

				X86_SET_REG(0);
				if (Disassemble)
				{
					APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_T (test register)\n"));
				continue;

			case AMODE_C: // modrm.reg = control register
				assert(X86Instruction->HasModRM);
				assert(Instruction->Type == ITYPE_MOV);
				if (!Decode) continue;
				Instruction->Groups |= ITYPE_SYSTEM;
				Instruction->NeedsEmulation = TRUE;
				Operand->Flags |= OP_REG;
				if (IS_AMD64()) X86Instruction->OperandSize = 8;
				switch (X86Instruction->OperandSize)
				{
					case 8:
					case 4:
					case 2:
						Operand->Register = X86_CONTROL_OFFSET + rex_modrm.reg;
						break;
					default:
						assert(0);
						return NULL;
				}

				X86_SET_REG(0);
				if (Disassemble)
				{
					APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_C (control register)\n"));
				continue;

			case AMODE_D: // modrm.reg = debug register
				assert(X86Instruction->HasModRM);
				assert(Instruction->Type == ITYPE_MOV);
				if (!Decode) continue;
				Instruction->NeedsEmulation = TRUE;
				Operand->Flags |= OP_REG;
				Instruction->Groups |= ITYPE_SYSTEM;
				Instruction->NeedsEmulation = TRUE;
				if (IS_AMD64()) X86Instruction->OperandSize = 8;
				switch (X86Instruction->OperandSize)
				{
					case 8:
					case 4:
					case 2:
						Operand->Register = X86_DEBUG_OFFSET + rex_modrm.reg;
						break;
					default:
						assert(0);
						return NULL;
				}

				X86_SET_REG(0);
				if (Disassemble)
				{
					APPENDS(X86_Registers[Operand->Register]);
					X86_WRITE_OPFLAGS();
				}
				//DISASM_OUTPUT(("[SetOperand] AMODE_D (debug register)\n"));
				continue;

			////////////////////////////////////////////////////////////
			// Mod R/M byte with memory or register
			////////////////////////////////////////////////////////////

			case AMODE_M: // memory only
				assert(X86Instruction->HasModRM);
				if (modrm.mod == 3)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: mod = 3 for AMODE_M (\"%s\")\n", VIRTUAL_ADDRESS, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}
				assert(X86Instruction->Segment == SEG_DS || X86Instruction->HasSegmentOverridePrefix);
				//DISASM_OUTPUT(("[SetOperand] AMODE_M (memory only)\n"));
				Address = SetModRM32(Instruction, Address, Operand, OperandIndex, SuppressErrors);
				if (!Address) return NULL;
				break;

			case AMODE_E: // general register or memory
				assert(X86Instruction->HasModRM);
				if (OperandType == OPTYPE_p && modrm.mod == 3)
				{
					if (!SuppressErrors) printf("[0x%08I64X] ERROR: mod = 3 for AMODE_E with OPTYPE_p (\"%s\")\n", VIRTUAL_ADDRESS, X86Instruction->Opcode.Mnemonic);
					goto abort;
				}

				//DISASM_OUTPUT(("[SetOperand] AMODE_E (general register or memory)\n"));
				Address = SetModRM32(Instruction, Address, Operand, OperandIndex, SuppressErrors);
				if (!Address) return NULL;
				if (Decode && (Instruction->Type == ITYPE_PUSH || Instruction->Type == ITYPE_POP))
				{
					assert(X86Instruction->OperandSize >= Operand->Length);
					Operand->Length = X86Instruction->OperandSize;
				}
				break;

			case AMODE_Q: // mmx register or memory address
				assert(X86Instruction->HasModRM);
				//DISASM_OUTPUT(("[SetOperand] AMODE_Q (MMX register or memory address)\n"));
				if (modrm.mod == 3) // it is a register
				{
					if (rex_modrm.rm > 7)
					{
						if (!SuppressErrors) printf("[0x%08I64X] ERROR: invalid mmx register %d for AMODE_P (\"%s\")\n", VIRTUAL_ADDRESS, rex_modrm.rm, X86Instruction->Opcode.Mnemonic);
						goto abort;
					}
					Operand->Register = X86_MMX_OFFSET + rex_modrm.rm;
					Operand->Flags |= OP_REG;
					X86_SET_REG(0);
				}
				else
				{
					Address = SetModRM32(Instruction, Address, Operand, OperandIndex, SuppressErrors);
					if (!Address) return NULL;
				}
				break;

			case AMODE_W: // xmm register or memory address
				assert(X86Instruction->HasModRM);
				//DISASM_OUTPUT(("[SetOperand] AMODE_W (XMM register or memory address)\n"));
				if (modrm.mod == 3) // it is a register
				{
					Operand->Register = X86_XMM_OFFSET + rex_modrm.rm;
					Operand->Flags |= OP_REG;
					X86_SET_REG(0);
				}
				else
				{
					Address = SetModRM32(Instruction, Address, Operand, OperandIndex, SuppressErrors);
					if (!Address) return NULL;
				}
				break;

			default:
				assert(0);
				return NULL;
		}

		if (!Decode) continue;

		// If this is reached then SetModRM32 was called
		if ((Operand->Flags & OP_ADDRESS))
		{
			assert(Operand->Length);
			switch (Operand->Register)
			{
				case X86_REG_BP:
				case X86_REG_EBP:
				case AMD64_REG_RBP:
					if (X86Instruction->Displacement > 0) Operand->Flags |= OP_PARAM;
					else Operand->Flags |= OP_LOCAL;
					break;
				default:
					break;
			}
		}

		if (Disassemble)
		{
			Index = OperandType >> OPTYPE_SHIFT;
			assert(Index > 0 && Index < MAX_OPTYPE_INDEX && OptypeHandlers[Index]);
			OptypeHandlers[Index](Instruction, Operand, OperandIndex);
			X86_WRITE_OPFLAGS();
		}
	}

	return Address;

abort:
	if (!SuppressErrors)
	{
#ifdef TEST_DISASM
		printf("Dump of 0x%04I64X:\n", VIRTUAL_ADDRESS);
		__try { DumpAsBytes(stdout, Instruction->Address, (ULONG_PTR)VIRTUAL_ADDRESS, 16, TRUE); }
		__except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {}
#endif
		fflush(stdout);
	}
	return NULL;
}

// NOTE: Address points one byte after ModRM
INTERNAL U8 *SetModRM16(INSTRUCTION *Instruction, U8 *Address, INSTRUCTION_OPERAND *Operand, U32 OperandIndex, BOOL SuppressErrors)
{
	MODRM modrm;
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;

	DISASM_OUTPUT(("[SetModRM16] Current instruction length = %d\n", Instruction->Length));
	modrm = X86Instruction->modrm;
	assert(!X86Instruction->rex_b);

	//
	// Both operands are registers
	// Condition: mod = 3
	//
	if (modrm.mod == 3)
	{
		//DISASM_OUTPUT(("[SetModRM16] Both regs (rm_reg %d)\n", modrm.rm));
		switch (Operand->Length)
		{
			case 4: Operand->Register = X86_32BIT_OFFSET + modrm.rm; break;
			case 2: Operand->Register = X86_16BIT_OFFSET + modrm.rm; break;
			case 1: Operand->Register = X86_8BIT_OFFSET + modrm.rm; break;
			default: assert(0); return NULL;
		}
		Operand->Flags |= OP_REG;
	}

	// 
	// Address is an absolute address (technically a 16-bit offset from DS:0)
	// Condition: mod = 0 and rm = 6
	//
	else if (modrm.mod == 0 && modrm.rm == 6)
	{
		//DISASM_OUTPUT(("[SetModRM16] Absolute addressing (displacement 0x%04X)\n", *(S16 *)Address));
		X86Instruction->Displacement = (S64)(*((S16 *)Address));
		if (IS_VALID_ADDRESS(X86Instruction->Displacement))
		{
			X86Instruction->HasFullDisplacement = TRUE;
			X86_SET_TARGET();
			Operand->Flags |= OP_GLOBAL;
		}
		X86_SET_ADDR();
		Operand->Flags |= OP_ADDRESS;
		INSTR_INC(2);
	}

	// Conditions:
	// (1) mod = 0 and rm != 6
	// (2) mod = 1-2 and rm = 0-7
	else
	{
		switch (modrm.mod)
		{
			case 0: // no displacement
				//DISASM_OUTPUT(("[SetModRM16] Indirect addressing (no displacement)\n"));
				break; 
			case 1: // 8-bit signed displacement
				//DISASM_OUTPUT(("[SetModRM16] Indirect addressing (displacement = 0x%02X, reg_rm = %d)\n", *(S8 *)Address, modrm.rm));
				X86Instruction->Displacement = (S64)(*((S8 *)Address));
				INSTR_INC(1); // increment Instruction->Length and address
				break;
			case 2: // 16-bit displacement
				//DISASM_OUTPUT(("[SetModRM16] Indirect addressing (displacement = 0x%04X, reg_rm = %d)\n", *(S16 *)Address, modrm.rm));
				X86Instruction->Displacement = (S64)(*((S16 *)Address));
				if (IS_VALID_ADDRESS(X86Instruction->Displacement))
				{
					Operand->Flags |= OP_GLOBAL;
					X86Instruction->HasFullDisplacement = TRUE;
				}
				INSTR_INC(2);
				break;
		}

		switch (modrm.rm)
		{
			case 0:
				//DISASM_OUTPUT(("[SetModRM16] Addressing mode [BX+SI]\n"));
				X86Instruction->BaseRegister = X86_REG_BX;
				X86Instruction->IndexRegister = X86_REG_SI;
				X86Instruction->HasIndexRegister = TRUE;
				break;
			case 1:
				//DISASM_OUTPUT(("[SetModRM16] Addressing mode [BX+DI]\n"));
				X86Instruction->BaseRegister = X86_REG_BX;
				X86Instruction->IndexRegister = X86_REG_DI;
				X86Instruction->HasIndexRegister = TRUE;
				break;
			case 2:
				//DISASM_OUTPUT(("[SetModRM16] Addressing mode [BP+SI]\n"));
				X86Instruction->BaseRegister = X86_REG_BP;
				X86Instruction->IndexRegister = X86_REG_SI;
				X86Instruction->HasIndexRegister = TRUE;
				X86_SET_SEG(REG_BP);
				break;
			case 3:
				//DISASM_OUTPUT(("[SetModRM16] Addressing mode [BP+DI]\n"));
				X86Instruction->BaseRegister = X86_REG_BP;
				X86Instruction->IndexRegister = X86_REG_DI;
				X86Instruction->HasIndexRegister = TRUE;
				X86_SET_SEG(REG_BP);
				break;
			case 4:
				//DISASM_OUTPUT(("[SetModRM16] Addressing mode [SI]\n"));
				X86Instruction->BaseRegister = X86_REG_SI;
				break;
			case 5:
				//DISASM_OUTPUT(("[SetModRM16] Addressing mode [DI]\n"));
				X86Instruction->BaseRegister = X86_REG_DI;
				break;
			case 6:
				//DISASM_OUTPUT(("[SetModRM16] Addressing mode [BP]\n"));
				X86Instruction->BaseRegister = X86_REG_BP;
				break;
			case 7:
				//DISASM_OUTPUT(("[SetModRM16] Addressing mode [BX]\n"));
				X86Instruction->BaseRegister = X86_REG_BX;
				break;
		}

		X86Instruction->HasBaseRegister = TRUE;
		Operand->Flags |= OP_ADDRESS | OP_REG;
		X86_SET_ADDR();
	}

	return Address;
}

// NOTE: Address points one byte after ModRM
INTERNAL U8 *SetModRM32(INSTRUCTION *Instruction, U8 *Address, INSTRUCTION_OPERAND *Operand, U32 OperandIndex, BOOL SuppressErrors)
{
	MODRM modrm;
	REX_MODRM rex_modrm;
	U32 i, ImmediateSize = 0;
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;

	if (X86Instruction->AddressSize == 2)
	{
		return SetModRM16(Instruction, Address, Operand, OperandIndex, SuppressErrors);
	}

	//DISASM_OUTPUT(("[SetModRM32] Length %d, modrm = 0x%02X\n", Instruction->Length, X86Instruction->modrm_b));
	modrm = X86Instruction->modrm;
	rex_modrm = X86Instruction->rex_modrm;

	//
	// Both operands are registers
	// Condition: mod = 3
	//
	if (modrm.mod == 3)
	{
		switch (Operand->Length)
		{
			case 8: Operand->Register = AMD64_64BIT_OFFSET + rex_modrm.rm; break;
			case 4: Operand->Register = X86_32BIT_OFFSET + rex_modrm.rm; CHECK_AMD64_REG(); break;
			case 2: Operand->Register = X86_16BIT_OFFSET + rex_modrm.rm; CHECK_AMD64_REG(); break;
			case 1: Operand->Register = X86_8BIT_OFFSET + rex_modrm.rm; if (X86Instruction->rex_b) CHECK_AMD64_REG(); break;
			default: assert(0); return NULL;
		}
		X86_SET_REG(rex_modrm.rm);
		Operand->Flags |= OP_REG;
	}

	// 
	// Address is an absolute address (technically a 32-bit offset from DS:0)
	// mod = 0 and rm = 5
	//
	else if (modrm.mod == 0 && modrm.rm == 5)
	{
		//DISASM_OUTPUT(("[SetModRM32] Absolute addressing (displacement 0x%08lX)\n", *(S32 *)Address));
		Operand->Flags |= OP_ADDRESS;
		X86Instruction->Displacement = (S64)*((S32 *)Address);
		INSTR_INC(4); // increment Instruction->Length and address

		if (IS_AMD64())
		{
			// RIP-relative addressing always replaced Disp32, even when using a 32-bit address space
			// (via address size override prefix)
			switch (X86Instruction->OperandSize)
			{
				case 8: Operand->Register = AMD64_REG_RIP; break;
				case 4: Operand->Register = X86_REG_EIP; break;
				case 2: Operand->Register = X86_REG_IP; break;
				default: assert(0); return NULL;
			}
			X86Instruction->BaseRegister = Operand->Register;
			X86Instruction->HasBaseRegister = TRUE;
			X86Instruction->Relative = TRUE;
			Operand->Flags |= OP_IPREL | OP_SIGNED | OP_REG;
			SANITY_CHECK_SEGMENT_OVERRIDE();
			if (!X86Instruction->HasSegmentOverridePrefix) X86Instruction->Segment = SEG_CS;
			X86Instruction->HasFullDisplacement = TRUE;

			// Since there may be an immediate value to follow, it is necessary
			// to determine the length in order get the proper offset
			//
			// Maybe there is a better way to do this, since this is wasteful
			// (the size of the immediate value will have to be decoded again later
			// in SetOperands)

			for (ImmediateSize = 0, i = OperandIndex+1; i < Instruction->OperandCount; i++)
			{
				if ((X86Instruction->Opcode.OperandFlags[i] & X86_AMODE_MASK) != AMODE_I) continue;
				else assert(!ImmediateSize);
				switch (X86Instruction->Opcode.OperandFlags[i] & X86_OPTYPE_MASK)
				{
					case OPTYPE_v:
						ImmediateSize = X86Instruction->OperandSize;
						break;
					case OPTYPE_z:
						switch (X86Instruction->OperandSize)
						{
							case 8: case 4: ImmediateSize = 4; break;
							case 2: ImmediateSize = 2; break;
							default: assert(0); return NULL;
						}
						break;
					case OPTYPE_b:
						ImmediateSize = 1;
						break;
					case OPTYPE_w:
						ImmediateSize = 2;
						break;
					case OPTYPE_1:
						break;
					default:
						assert(0);
						break;
				}
			}

			Operand->TargetAddress = ApplyDisplacement((U64)Address + ImmediateSize, Instruction);
		}
		else if (IS_VALID_ADDRESS(X86Instruction->Displacement))
		{
			X86_SET_TARGET();
			Operand->Flags |= OP_GLOBAL;
			X86Instruction->HasFullDisplacement = TRUE;
		}

		X86_SET_ADDR();
	}

	//
	// Addressing mode indicated by SIB byte
	// Condition: mod = 0-2 and rm = 4
	//
	else if (modrm.rm == 4)
	{
		// The X86_SET_*() is called from within SetSIB()
		Address = SetSIB(Instruction, Address, Operand, OperandIndex, SuppressErrors);
		if (!Address)
		{
			assert(0);
			return NULL;
		}

		if (X86Instruction->sib.base != 5) // if base == 5, the displacement is handled in SetSIB
		{
			switch (modrm.mod)
			{
				case 1: // 8-bit displacement
					//DISASM_OUTPUT(("[SetModRM32] After SIB: displacement 0x%02X\n", *((S8 *)Address)));
					X86Instruction->Displacement = (S64)(*((S8 *)Address));
					INSTR_INC(1); // increment Instruction->Length and address
					break;
				case 2: // 32-bit displacement
					//DISASM_OUTPUT(("[SetModRM32] After SIB: displacement 0x%08lX\n", *((S32 *)Address)));
					X86Instruction->Displacement = (S64)*((S32 *)Address);
					if (IS_VALID_ADDRESS(X86Instruction->Displacement))
					{
						Operand->Flags |= OP_GLOBAL;
						X86Instruction->HasFullDisplacement = TRUE;
					}
					INSTR_INC(4); // increment Instruction->Length and address
					break;
			}	
		}
	}

	// Indirect addressing
	// Conditions:
	// (1) mod = 0 and (rm = 0-3 or 6-7)
	// (2) mod = 1-2 and rm != 4
	else
	{
		switch (X86Instruction->AddressSize)
		{
			case 8: Operand->Register = AMD64_64BIT_OFFSET + rex_modrm.rm; break;
			case 4: Operand->Register = X86_32BIT_OFFSET + rex_modrm.rm; CHECK_AMD64_REG(); break;
			default: assert(0); return NULL;
		}
		X86Instruction->BaseRegister = Operand->Register;
		X86Instruction->HasBaseRegister = TRUE;
		Operand->Flags |= OP_ADDRESS | OP_REG;
		X86_SET_SEG(rex_modrm.rm);
		X86_SET_ADDR();

		switch (modrm.mod)
		{
			case 0: // no displacement
				//DISASM_OUTPUT(("[SetModRM32] Indirect addressing (no displacement, reg_rm = %d)\n", rex_modrm.rm));
				break; 
			case 1: // 8-bit signed displacement
				//DISASM_OUTPUT(("[SetModRM32] Indirect addressing (displacement = 0x%02X, reg_rm = %d)\n", *(S8 *)Address, rex_modrm.rm));
				X86Instruction->Displacement = (S64)(*((S8 *)Address));
				INSTR_INC(1); // increment Instruction->Length and address
				break;
			case 2: // 32-bit displacement
				//DISASM_OUTPUT(("[SetModRM32] Indirect addressing (displacement = 0x%08lX, reg_rm = %d)\n", *(S32 *)Address, rex_modrm.rm));
				X86Instruction->Displacement = (S64)*((S32 *)Address);
				if (IS_VALID_ADDRESS(X86Instruction->Displacement))
				{
					Operand->Flags |= OP_GLOBAL;
					X86Instruction->HasFullDisplacement = TRUE;
				}
				INSTR_INC(4); // increment Instruction->Length and address
				break;
		}
	}

	return Address;
}

// NOTE: Address points at SIB
INTERNAL U8 *SetSIB(INSTRUCTION *Instruction, U8 *Address, INSTRUCTION_OPERAND *Operand, U32 OperandIndex, BOOL SuppressErrors)
{
	REX rex;
	SIB sib;
	REX_SIB rex_sib;
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;

	X86Instruction->sib_b = *Address;
	SET_SIB(X86Instruction->sib, *Address);
	sib = X86Instruction->sib;
	rex = X86Instruction->rex;
	SET_REX_SIB(X86Instruction->rex_sib, rex, sib);
	rex_sib = X86Instruction->rex_sib;

	//if (!X86Instruction->rex_b) DISASM_OUTPUT(("[0x%08I64X] SIB = 0x%02X (scale=%d, index=%d, base=%d)\n", VIRTUAL_ADDRESS, *Address, sib.scale, sib.index, sib.base)); \
	//else DISASM_OUTPUT(("[0x%08I64X] SIB = 0x%02X (scale=%d, index=%d, base=%d)\n", VIRTUAL_ADDRESS, *Address, sib.scale, rex_sib.index, rex_sib.base)); \
	//DISASM_OUTPUT(("[SetSIB] Current instruction length = %d\n", Instruction->Length));

	Operand->Flags |= OP_ADDRESS;
	X86_SET_ADDR();
	INSTR_INC(1); // increment Instruction->Length and address

	if (sib.base == 5)
	{
		switch (X86Instruction->modrm.mod)
		{
			case 0:
				X86Instruction->Displacement = (S64)*((S32 *)Address);
				if (IS_VALID_ADDRESS(X86Instruction->Displacement))
				{
					X86Instruction->HasFullDisplacement = TRUE;
					X86_SET_TARGET();
					Operand->Flags |= OP_GLOBAL;
				}
				INSTR_INC(4);
				break;
			case 1:
				X86Instruction->Displacement = (S64)(*((S8 *)Address));
				if (rex_sib.base == 5)
				{
					switch (X86Instruction->AddressSize)
					{
						case 8: Operand->Register = AMD64_REG_RBP; break;
						case 4: Operand->Register = X86_REG_EBP; break;
						default: assert(0); return NULL;
					}
					X86_SET_SEG(REG_EBP);
				}
				else
				{
					Operand->Register = AMD64_REG_R13;
				}

				X86Instruction->BaseRegister = Operand->Register;
				X86Instruction->HasBaseRegister = TRUE;
				Operand->Flags |= OP_REG;
				INSTR_INC(1);
				break;
			case 2:
				X86Instruction->Displacement = (S64)*((S32 *)Address);
				if (rex_sib.base == 5)
				{
					switch (X86Instruction->AddressSize)
					{
						case 8: Operand->Register = AMD64_REG_RBP; break;
						case 4: Operand->Register = X86_REG_EBP; break;
						default: assert(0); return NULL;
					}
					X86_SET_SEG(REG_EBP);
				}
				else
				{
					Operand->Register = AMD64_REG_R13;
				}

				if (IS_VALID_ADDRESS(X86Instruction->Displacement))
				{
					Operand->Flags |= OP_GLOBAL;
					X86Instruction->HasFullDisplacement = TRUE;
				}
				X86Instruction->BaseRegister = Operand->Register;
				X86Instruction->HasBaseRegister = TRUE;
				Operand->Flags |= OP_REG;
				INSTR_INC(4);
				break;
		}
	}
	else
	{
		switch (X86Instruction->AddressSize)
		{
			case 8: Operand->Register = AMD64_64BIT_OFFSET + rex_sib.base; break;
			case 4: Operand->Register = X86_32BIT_OFFSET + rex_sib.base; CHECK_AMD64_REG(); break;
			default: assert(0); return NULL;
		}
		X86Instruction->BaseRegister = Operand->Register;
		X86Instruction->HasBaseRegister = TRUE;
		X86_SET_SEG(rex_sib.base);
		Operand->Flags |= OP_REG;
	}

	if (rex_sib.index != 4)
	{
		switch (X86Instruction->AddressSize)
		{
			case 8:
				X86Instruction->IndexRegister = AMD64_64BIT_OFFSET + rex_sib.index;
				break;
			case 4:
				X86Instruction->IndexRegister = X86_32BIT_OFFSET + rex_sib.index;
				break;
			default:
				fflush(stdout);
				assert(0);
				return NULL;
		}

		Operand->TargetAddress = 0;
		X86Instruction->HasIndexRegister = TRUE;
		//DISASM_OUTPUT(("[SetSIB] Index register = %s\n", X86_Registers[X86_32BIT_OFFSET + rex_sib.index]));

		switch (sib.scale)
		{
			case 0: X86Instruction->Scale = 1; break;
			case 1: X86Instruction->Scale = 2; break;
			case 2: X86Instruction->Scale = 4; break;
			case 3: X86Instruction->Scale = 8; break;
		}
		//DISASM_OUTPUT(("[SetSIB] Scale = %d\n", X86Instruction->Scale));
	}

	return Address;
}

INTERNAL U64 ApplyDisplacement(U64 Address, INSTRUCTION *Instruction)
{
	X86_INSTRUCTION *X86Instruction = &Instruction->X86;

#ifdef SUPPORT_WRAPAROUND
	U64 VirtualAddress = Address + Instruction->VirtualAddressDelta;
	switch (X86Instruction->OperandSize)
	{
		case 8:
		{
			U64 PreAddr = VirtualAddress;
			U64 PostAddr = PreAddr + X86Instruction->Displacement;
			return Address + (PostAddr - PreAddr);
		}
		case 4:
		{
			// We have to do this carefully...
			// If EIP = FFFFF000 and Displacement=2000 then the final IP should be 1000
			// due to wraparound
			U32 PreAddr = (U32)VirtualAddress;
			U32 PostAddr = PreAddr + (S32)X86Instruction->Displacement;
			return Address + (PostAddr - PreAddr);
		}
		case 2:
		{
			// We have to do this carefully...
			// If IP = F000 and Displacement=2000 then the final IP should be 1000
			// due to wraparound
			U16 PreAddr = (U16)VirtualAddress;
			U16 PostAddr = PreAddr + (S16)X86Instruction->Displacement;
			return Address + (PostAddr - PreAddr);
		}
		default:
			assert(0);
			return 0;
	}
#else
	return (Address + X86Instruction->Displacement);
#endif
}



INTERNAL BOOL IsValidLockPrefix(X86_INSTRUCTION *X86Instruction, U8 Opcode, U32 OpcodeLength, U8 Group, U8 OpcodeExtension)
{
	switch (OpcodeLength)
	{
		case 1:
			switch (X86_LockPrefix_1[Opcode])
			{
				case 0: // instruction can't be locked
					return FALSE;
				case 1: // instruction can be locked
					break;
				case GR:
					assert(Group);
					if (!X86_LockPrefix_Groups[Group-1][OpcodeExtension]) return FALSE;
					break;
				default:
					assert(0);
					return FALSE;
			}
			break;

		case 2:
		case 3:
			switch (X86_LockPrefix_2[Opcode])
			{
				case 0: // lock prefix is not acceptable
					return FALSE;
				case 1: // lock prefix allowed
					break;
				case GR:
					assert(Group);
					if (!X86_LockPrefix_Groups[Group-1][OpcodeExtension]) return FALSE;
					break;
				default:
					assert(0);
					return FALSE;
			}
			break;

		default:
			assert(0);
			return FALSE;
	}

	if (!X86Instruction->HasModRM || X86Instruction->modrm.mod == 3 || !X86Instruction->HasDstAddressing)
	{
		DISASM_OUTPUT(("[0x%08I64X] ERROR: Instruction \"%s\" with LOCK prefix has invalid ModRM addressing\n", VIRTUAL_ADDRESS, X86Instruction->Opcode.Mnemonic, X86Instruction->Instruction->Address));
		return FALSE;
	}

	return TRUE;
}
