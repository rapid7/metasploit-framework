
/*
 * libdasm -- simple x86 disassembly library
 * (c) 2004 - 2005  jt / nologin.org
 *
 * libdasm.h:
 * Definitions for structures, functions and other weird stuff
 *
 */


#ifndef _LIBDASM_H
#define _LIBDASM_H

#ifdef __cplusplus
extern "C" {
#endif

#define __LIBDASM_VERSION__     0x01040000

#define GET_VERSION_MAJOR  \
	(__LIBDASM_VERSION__ & 0xff000000) >> 24
#define GET_VERSION_MINOR1 \
	(__LIBDASM_VERSION__ & 0x00ff0000) >> 16
#define GET_VERSION_MINOR2 \
	(__LIBDASM_VERSION__ & 0x0000ff00) >> 8
#define GET_VERSION_MINOR3 \
	(__LIBDASM_VERSION__ & 0x000000ff)

// Data types

#if _WIN32
#include <windows.h>
#define __inline__ __inline
#define snprintf _snprintf
typedef unsigned __int64 QWORD;		// for MSVC
typedef signed   __int8  SBYTE;
typedef signed   __int16 SWORD;
typedef signed   __int32 SDWORD;
typedef signed   __int64 SQWORD;
#else
#if defined __sun
#define BYTE_ORDER 1234
#define BIG_ENDIAN 1234
#define LITTLE_ENDIAN 4321
#define u_int8_t uint8_t
#define u_int16_t uint16_t
#define u_int32_t uint32_t
#define u_int64_t uint64_t

#endif // other *nix
#include <sys/types.h>
typedef u_int8_t  BYTE;
typedef u_int16_t WORD;
typedef u_int32_t DWORD;
typedef u_int64_t QWORD;
typedef int8_t    SBYTE;
typedef int16_t   SWORD;
typedef int32_t   SDWORD;
typedef int64_t   SQWORD;
#endif

// Define endianess

#ifndef __X86__
// These should catch x86 with most compilers
#if defined _X86_ || defined _i386_ || defined __i386__
#define __X86__
#endif
#endif

#ifndef __LITTLE_ENDIAN__
// These should catch little-endian with most compilers
#if (BYTE_ORDER == LITTLE_ENDIAN) || defined __X86__ || defined _ALPHA_
#define __LITTLE_ENDIAN__
#endif
#endif


// Registers
#define REGISTER_EAX 0
#define REGISTER_ECX 1
#define REGISTER_EDX 2
#define REGISTER_EBX 3
#define REGISTER_ESP 4
#define REGISTER_EBP 5
#define REGISTER_ESI 6
#define REGISTER_EDI 7
#define REGISTER_NOP 8	// no register defined

// Registers
#define REG_EAX REGISTER_EAX
#define REG_AX REG_EAX
#define REG_AL REG_EAX
#define REG_ES REG_EAX          // Just for reg_table consistence
#define REG_ST0 REG_EAX         // Just for reg_table consistence
#define REG_ECX REGISTER_ECX
#define REG_CX REG_ECX
#define REG_CL REG_ECX
#define REG_CS REG_ECX
#define REG_ST1 REG_ECX
#define REG_EDX REGISTER_EDX
#define REG_DX REG_EDX
#define REG_DL REG_EDX
#define REG_SS REG_EDX
#define REG_ST2 REG_EDX
#define REG_EBX REGISTER_EBX
#define REG_BX REG_EBX
#define REG_BL REG_EBX
#define REG_DS REG_EBX
#define REG_ST3 REG_EBX
#define REG_ESP REGISTER_ESP
#define REG_SP REG_ESP
#define REG_AH REG_ESP          // Just for reg_table consistence
#define REG_FS REG_ESP
#define REG_ST4 REG_ESP
#define REG_EBP REGISTER_EBP
#define REG_BP REG_EBP
#define REG_CH REG_EBP
#define REG_GS REG_EBP
#define REG_ST5 REG_EBP
#define REG_ESI REGISTER_ESI
#define REG_SI REG_ESI
#define REG_DH REG_ESI
#define REG_ST6 REG_ESI
#define REG_EDI REGISTER_EDI
#define REG_DI REG_EDI
#define REG_BH REG_EDI
#define REG_ST7 REG_EDI
#define REG_NOP REGISTER_NOP

// Register types
#define REGISTER_TYPE_GEN	1
#define REGISTER_TYPE_SEGMENT   2
#define REGISTER_TYPE_DEBUG     3
#define REGISTER_TYPE_CONTROL	4
#define REGISTER_TYPE_TEST      5
#define REGISTER_TYPE_XMM       6
#define REGISTER_TYPE_MMX       7
#define REGISTER_TYPE_FPU       8

// Disassembling mode
enum Mode {
	MODE_32,	// 32-bit
	MODE_16		// 16-bit
};

// Disassembling format
enum Format {
	FORMAT_ATT,
	FORMAT_INTEL,
};

// Instruction types (just the most common ones atm)
enum Instruction {
	// Integer instructions
	INSTRUCTION_TYPE_ASC,	// aaa, aam, etc.
	INSTRUCTION_TYPE_DCL,	// daa, das
	INSTRUCTION_TYPE_MOV,
	INSTRUCTION_TYPE_MOVSR,	// segment register
	INSTRUCTION_TYPE_ADD,
	INSTRUCTION_TYPE_XADD,
	INSTRUCTION_TYPE_ADC,
	INSTRUCTION_TYPE_SUB,
	INSTRUCTION_TYPE_SBB,
	INSTRUCTION_TYPE_INC,
	INSTRUCTION_TYPE_DEC,
	INSTRUCTION_TYPE_DIV,
	INSTRUCTION_TYPE_IDIV,
	INSTRUCTION_TYPE_NOT,
	INSTRUCTION_TYPE_NEG,
	INSTRUCTION_TYPE_STOS,
	INSTRUCTION_TYPE_LODS,
	INSTRUCTION_TYPE_SCAS,
	INSTRUCTION_TYPE_MOVS,
	INSTRUCTION_TYPE_MOVSX,
	INSTRUCTION_TYPE_MOVZX,
	INSTRUCTION_TYPE_CMPS,
	INSTRUCTION_TYPE_SHX,	// signed/unsigned shift left/right
	INSTRUCTION_TYPE_ROX,	// signed/unsigned rot left/right
	INSTRUCTION_TYPE_MUL,
	INSTRUCTION_TYPE_IMUL,
	INSTRUCTION_TYPE_EIMUL, // "extended" imul with 2-3 operands
	INSTRUCTION_TYPE_XOR,
	INSTRUCTION_TYPE_LEA,
	INSTRUCTION_TYPE_XCHG,
	INSTRUCTION_TYPE_CMP,
	INSTRUCTION_TYPE_TEST,
	INSTRUCTION_TYPE_PUSH,
	INSTRUCTION_TYPE_AND,
	INSTRUCTION_TYPE_OR,
	INSTRUCTION_TYPE_POP,
	INSTRUCTION_TYPE_JMP,
	INSTRUCTION_TYPE_JMPC,	// conditional jump
	INSTRUCTION_TYPE_SETC,	// conditional byte set
	INSTRUCTION_TYPE_MOVC,	// conditional mov
	INSTRUCTION_TYPE_LOOP,
	INSTRUCTION_TYPE_CALL,
	INSTRUCTION_TYPE_RET,
	INSTRUCTION_TYPE_INT,	// interrupt
	INSTRUCTION_TYPE_BT,	// bit tests
	INSTRUCTION_TYPE_BTS,
	INSTRUCTION_TYPE_BTR,
	INSTRUCTION_TYPE_BTC,
	INSTRUCTION_TYPE_BSF,
	INSTRUCTION_TYPE_BSR,
	INSTRUCTION_TYPE_BSWAP,
	INSTRUCTION_TYPE_SGDT,
	INSTRUCTION_TYPE_SIDT,
	INSTRUCTION_TYPE_SLDT,
	INSTRUCTION_TYPE_LFP,
	// FPU instructions
	INSTRUCTION_TYPE_FCMOVC, // float conditional mov
	INSTRUCTION_TYPE_FADD,
	INSTRUCTION_TYPE_FADDP,
	INSTRUCTION_TYPE_FIADD,
	INSTRUCTION_TYPE_FSUB,
	INSTRUCTION_TYPE_FSUBP,
	INSTRUCTION_TYPE_FISUB,
	INSTRUCTION_TYPE_FSUBR,
	INSTRUCTION_TYPE_FSUBRP,
	INSTRUCTION_TYPE_FISUBR,
	INSTRUCTION_TYPE_FMUL,
	INSTRUCTION_TYPE_FMULP,
	INSTRUCTION_TYPE_FIMUL,
	INSTRUCTION_TYPE_FDIV,
	INSTRUCTION_TYPE_FDIVP,
	INSTRUCTION_TYPE_FDIVR,
	INSTRUCTION_TYPE_FDIVRP,
	INSTRUCTION_TYPE_FIDIV,
	INSTRUCTION_TYPE_FIDIVR,
	INSTRUCTION_TYPE_FCOM,
	INSTRUCTION_TYPE_FCOMP,
	INSTRUCTION_TYPE_FCOMPP,
	INSTRUCTION_TYPE_FCOMI,
	INSTRUCTION_TYPE_FCOMIP,
	INSTRUCTION_TYPE_FUCOM,
	INSTRUCTION_TYPE_FUCOMP,
	INSTRUCTION_TYPE_FUCOMPP,
	INSTRUCTION_TYPE_FUCOMI,
	INSTRUCTION_TYPE_FUCOMIP,
	INSTRUCTION_TYPE_FST,
	INSTRUCTION_TYPE_FSTP,
	INSTRUCTION_TYPE_FIST,
	INSTRUCTION_TYPE_FISTP,
	INSTRUCTION_TYPE_FISTTP,
	INSTRUCTION_TYPE_FLD,
	INSTRUCTION_TYPE_FILD,
	INSTRUCTION_TYPE_FICOM,
	INSTRUCTION_TYPE_FICOMP,
	INSTRUCTION_TYPE_FFREE,
	INSTRUCTION_TYPE_FFREEP,
	INSTRUCTION_TYPE_FXCH,
	INSTRUCTION_TYPE_FPU,	// Other FPU instructions

	INSTRUCTION_TYPE_MMX,	// Other MMX instructions

	INSTRUCTION_TYPE_SSE,	// Other SSE instructions

	INSTRUCTION_TYPE_OTHER,	// Other instructions :-)
	INSTRUCTION_TYPE_PRIV	// Privileged instruction
};

// Operand types
enum Operand {
	OPERAND_TYPE_NONE,	// operand not present
	OPERAND_TYPE_MEMORY,	// memory operand ([eax], [0], etc.)
	OPERAND_TYPE_REGISTER,	// register operand (eax, mm0, etc.)
	OPERAND_TYPE_IMMEDIATE,	// immediate operand (0x1234)
};

// Structure definitions

// struct INST is used internally by the library
typedef struct _INST {
	DWORD type;		// Instruction type and flags
	const char *mnemonic;	// Instruction mnemonic
	int flags1;		// First operand flags (if any)
	int flags2;		// Second operand flags (if any)
	int flags3;		// Additional operand flags (if any)
	int modrm;		// Is MODRM byte present?
} INST, *PINST;

// Operands for the instruction
typedef struct _OPERAND {
	enum Operand type;	// Operand type (register, memory, etc)
	int reg;		// Register (if any)
	int basereg;		// Base register (if any)
	int indexreg;		// Index register (if any)
	int scale;		// Scale (if any)
	int dispbytes;		// Displacement bytes (0 = no displacement)
	int dispoffset;		// Displacement value offset
	int immbytes;		// Immediate bytes (0 = no immediate)
	int immoffset;		// Immediate value offset
	int sectionbytes;	// Section prefix bytes (0 = no section prefix)
	WORD section;		// Section prefix value
	DWORD displacement;	// Displacement value
	DWORD immediate;	// Immediate value
	int flags;		// Operand flags
} OPERAND, *POPERAND;

// struct INSTRUCTION is used to interface the library
typedef struct _INSTRUCTION {
	int length;		// Instruction length
	enum Instruction type;	// Instruction type
	enum Mode mode;		// Addressing mode
	BYTE opcode;		// Actual opcode
	BYTE modrm;		// MODRM byte
	BYTE sib;		// SIB byte
	int extindex;		// Extension table index
	int fpuindex;		// FPU table index
	int dispbytes;		// Displacement bytes (0 = no displacement)
	int immbytes;		// Immediate bytes (0 = no immediate)
	int sectionbytes;	// Section prefix bytes (0 = no section prefix)
	OPERAND op1;		// First operand (if any)
	OPERAND op2;		// Second operand (if any)
	OPERAND op3;		// Additional operand (if any)
	PINST ptr;		// Pointer to instruction table
	int flags;		// Instruction flags
} INSTRUCTION, *PINSTRUCTION;


// Function definitions

int get_instruction(
	INSTRUCTION *inst,	// pointer to INSTRUCTION structure
	BYTE *addr,		// code buffer
	enum Mode mode		// mode: MODE_32 or MODE_16
);

// Get complete instruction string
int get_instruction_string(
	INSTRUCTION *inst,	// pointer to INSTRUCTION structure
        enum Format format,	// instruction format: FORMAT_ATT or FORMAT_INTEL
	DWORD offset,		// instruction absolute address
	char *string,		// string buffer
	int length		// string length
);

// Get mnemonic string
int get_mnemonic_string(
	INSTRUCTION *inst,	// pointer to INSTRUCTION structure
        enum Format format,	// instruction format: FORMAT_ATT or FORMAT_INTEL
	char *string,		// string buffer
	int length		// string length
);

// Get individual operand string
int get_operand_string(
	INSTRUCTION *inst,	// pointer to INSTRUCTION structure
	POPERAND op,		// pointer to OPERAND structure
        enum Format format,	// instruction format: FORMAT_ATT or FORMAT_INTEL
	DWORD offset,		// instruction absolute address
	char *string,		// string buffer
	int length		// string length
);

// Helper functions

int get_register_type(
	POPERAND op
);
int get_operand_type(
	POPERAND op
);
int get_operand_register(
	POPERAND op
);
int get_operand_basereg(
	POPERAND op
);
int get_operand_indexreg(
	POPERAND op
);
int get_operand_scale(
	POPERAND op
);
int get_operand_immediate(
	POPERAND op,
	DWORD *imm		// returned immediate value
);
int get_operand_displacement(
	POPERAND op,
	DWORD *disp		// returned displacement value
);
POPERAND get_source_operand(
	PINSTRUCTION inst
);
POPERAND get_destination_operand(
	PINSTRUCTION inst
);


// Instruction flags (prefixes)

// Group 1
#define MASK_PREFIX_G1(x) ((x) & 0xff000000) >> 24
#define PREFIX_LOCK			0x01000000	// 0xf0
#define PREFIX_REPNE			0x02000000	// 0xf2
#define PREFIX_REP			0x03000000	// 0xf3
#define PREFIX_REPE			0x03000000	// 0xf3
// Group 2
#define MASK_PREFIX_G2(x) ((x) & 0x00ff0000) >> 16
#define PREFIX_ES_OVERRIDE		0x00010000	// 0x26
#define PREFIX_CS_OVERRIDE		0x00020000	// 0x2e
#define PREFIX_SS_OVERRIDE		0x00030000	// 0x36
#define PREFIX_DS_OVERRIDE		0x00040000	// 0x3e
#define PREFIX_FS_OVERRIDE		0x00050000	// 0x64
#define PREFIX_GS_OVERRIDE		0x00060000	// 0x65
// Group 3 & 4
#define MASK_PREFIX_G3(x)	 ((x) & 0x0000ff00) >> 8
#define MASK_PREFIX_OPERAND(x)	 ((x) & 0x00000f00) >> 8
#define MASK_PREFIX_ADDR(x)	 ((x) & 0x0000f000) >> 12
#define PREFIX_OPERAND_SIZE_OVERRIDE	0x00000100	// 0x66
#define PREFIX_ADDR_SIZE_OVERRIDE	0x00001000	// 0x67

// Extensions

#define MASK_EXT(x) ((x) & 0x000000ff)
#define EXT_G1_1	0x00000001
#define EXT_G1_2	0x00000002
#define EXT_G1_3	0x00000003
#define EXT_G2_1	0x00000004
#define EXT_G2_2	0x00000005
#define EXT_G2_3	0x00000006
#define EXT_G2_4	0x00000007
#define EXT_G2_5	0x00000008
#define EXT_G2_6	0x00000009
#define EXT_G3_1	0x0000000a
#define EXT_G3_2	0x0000000b
#define EXT_G4		0x0000000c
#define EXT_G5		0x0000000d
#define EXT_G6		0x0000000e
#define EXT_G7		0x0000000f
#define EXT_G8		0x00000010
#define EXT_G9		0x00000011
#define EXT_GA		0x00000012
#define EXT_GB		0x00000013
#define EXT_GC		0x00000014
#define EXT_GD		0x00000015
#define EXT_GE		0x00000016
#define EXT_GF		0x00000017
#define EXT_G0		0x00000018

// Extra groups for 2 and 3-byte opcodes, and FPU stuff
#define EXT_T2		0x00000020	// opcode table 2
#define EXT_CP		0x00000030	// co-processor

// Instruction type flags

#define TYPE_3		0x80000000
#define MASK_TYPE_FLAGS(x) ((x) & 0xff000000)
#define MASK_TYPE_VALUE(x) ((x) & 0x00ffffff)


// Operand flags

#define FLAGS_NONE 0

// Operand Addressing Methods, from the Intel manual
#define MASK_AM(x) ((x) & 0x00ff0000)
#define AM_A 0x00010000		// Direct address with segment prefix
#define AM_C 0x00020000		// MODRM reg field defines control register
#define AM_D 0x00030000		// MODRM reg field defines debug register
#define AM_E 0x00040000		// MODRM byte defines reg/memory address
#define AM_G 0x00050000		// MODRM byte defines general-purpose reg
#define AM_I 0x00060000		// Immediate data follows
#define AM_J 0x00070000		// Immediate value is relative to EIP
#define AM_M 0x00080000		// MODRM mod field can refer only to memory
#define AM_O 0x00090000		// Displacement follows (without modrm/sib)
#define AM_P 0x000a0000		// MODRM reg field defines MMX register
#define AM_Q 0x000b0000		// MODRM defines MMX register or memory 
#define AM_R 0x000c0000		// MODRM mod field can only refer to register
#define AM_S 0x000d0000		// MODRM reg field defines segment register
#define AM_T 0x000e0000		// MODRM reg field defines test register
#define AM_V 0x000f0000		// MODRM reg field defines XMM register
#define AM_W 0x00100000		// MODRM defines XMM register or memory 
// Extra addressing modes used in this implementation
#define AM_I1  0x00200000	// Immediate byte 1 encoded in instruction
#define AM_REG 0x00210000	// Register encoded in instruction
#define AM_IND 0x00220000	// Register indirect encoded in instruction

// Operand Types, from the intel manual
#define MASK_OT(x) ((x) & 0xff000000)
#define OT_a  0x01000000
#define OT_b  0x02000000	// always 1 byte
#define OT_c  0x03000000	// byte or word, depending on operand
#define OT_d  0x04000000	// double-word
#define OT_q  0x05000000	// quad-word
#define OT_dq 0x06000000	// double quad-word
#define OT_v  0x07000000	// word or double-word, depending on operand
#define OT_w  0x08000000	// always word
#define OT_p  0x09000000	// 32-bit or 48-bit pointer
#define OT_pi 0x0a000000	// quadword MMX register
#define OT_pd 0x0b000000	// 128-bit double-precision float
#define OT_ps 0x0c000000	// 128-bit single-precision float
#define OT_s  0x0d000000	// 6-byte pseudo descriptor
#define OT_sd 0x0e000000	// Scalar of 128-bit double-precision float
#define OT_ss 0x0f000000	// Scalar of 128-bit single-precision float
#define OT_si 0x10000000	// Doubleword integer register
#define OT_t  0x11000000	// 80-bit packed FP data

// Operand permissions
#define MASK_PERMS(x) ((x) & 0x0000f000)
#define P_r   0x00004000	// Read
#define P_w   0x00002000	// Write
#define P_x   0x00001000	// Execute

// Additional operand flags
#define MASK_FLAGS(x) ((x) & 0x00000f00)
#define F_s   0x00000100	// sign-extend 1-byte immediate
#define F_r   0x00000200	// use segment register
#define F_f   0x00000400	// use FPU register

// Mask 0x000000f0 unused atm

// Operand register mask
#define MASK_REG(x) ((x) & 0x0000000f)



// MODRM byte
#define MASK_MODRM_MOD(x) (((x) & 0xc0) >> 6)
#define MASK_MODRM_REG(x) (((x) & 0x38) >> 3)
#define MASK_MODRM_RM(x)   ((x) & 0x7)

// SIB byte
#define MASK_SIB_SCALE(x) MASK_MODRM_MOD(x)
#define MASK_SIB_INDEX(x) MASK_MODRM_REG(x)
#define MASK_SIB_BASE(x)  MASK_MODRM_RM(x)


#ifdef __cplusplus
}
#endif

#endif
