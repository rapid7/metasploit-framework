// Copyright (C) 2004, Matt Conover (mconover@gmail.com)
#ifndef X86_DISASM_H
#define X86_DISASM_H
#ifdef __cplusplus
extern "C" {
#endif

// NOTE: the processor may actually accept less than this amount (officially 15)
// #define AMD64_MAX_INSTRUCTION_LEN 15 // theoretical max 25=5+2+1+1+8+8
#define AMD64_MAX_PREFIX_LENGTH 5 // 4 legacy + 1 rex
#define AMD64_MAX_ADDRESS_LENGTH 18 // modrm + sib + 8 byte displacement + 8 byte immediate value

// NOTE: the processor may actually accept less than this amount (officially 15)
#define X86_MAX_INSTRUCTION_LEN 15 // theoretical 16=4+2+1+1+4+4
#define X86_MAX_PREFIX_LENGTH 4
#define X86_MAX_OPCODE_LENGTH 3 // third byte is either a suffix or prefix
#define X86_MAX_ADDRESS_LENGTH 10 // modrm + sib + 4 byte displacement + 4 byte immediate value
#define X86_MAX_OPERANDS 3

#define X86_PREFIX(a) ((a)->MnemonicFlags == ITYPE_EXT_PREFIX)
#define X86_SPECIAL_EXTENSION(a) ((a)->MnemonicFlags & (ITYPE_EXT_MODRM|ITYPE_EXT_FPU|ITYPE_EXT_SUFFIX|ITYPE_EXT_64))
#define X86_EXTENDED_OPCODE(a) ((a)->Table)
#define X86_INVALID(a) (!(a)->MnemonicFlags && !(a)->Table)
#define X86_OPERAND_COUNT(a) ((a)->OperandFlags[0] ? ((a)->OperandFlags[1] ? ((a)->OperandFlags[2] ? 3 : 2) : 1) : 0)
#define X86_GET_CATEGORY(p) ((p)->MnemonicFlags & ITYPE_GROUP_MASK)
#define X86_GET_TYPE(p) ((p)->MnemonicFlags & ITYPE_TYPE_MASK)

// Various instructions being specially decoded
#define X86_TWO_BYTE_OPCODE 0x0f
#define PREFIX_SEGMENT_OVERRIDE_ES 0x26
#define PREFIX_SEGMENT_OVERRIDE_CS 0x2e
#define PREFIX_BRANCH_NOT_TAKEN 0x2e // used only with conditional jumps
#define PREFIX_SEGMENT_OVERRIDE_SS 0x36
#define PREFIX_SEGMENT_OVERRIDE_DS 0x3e
#define PREFIX_BRANCH_TAKEN 0x3e // used only with conditional jumps
#define PREFIX_SEGMENT_OVERRIDE_FS 0x64
#define PREFIX_SEGMENT_OVERRIDE_GS 0x65
#define PREFIX_OPERAND_SIZE 0x66
#define PREFIX_ADDRESS_SIZE 0x67
#define PREFIX_LOCK 0xf0
#define PREFIX_REPNE 0xf2
#define PREFIX_REP 0xf3

//////////////////////////////////////////////////////////////////
// Implicit operand handling
//////////////////////////////////////////////////////////////////

#define X86_AMODE_MASK   0x00FF0000 // bits 16-23 (AMODE_*)
#define X86_OPFLAGS_MASK 0x0000FF80 // bits 7-15 (OPTYPE_*)
#define X86_OPTYPE_MASK  0xFF0000FF // bits 0-7 (OPTYPE_* below + OP_REG) and 24-31 (OPTYPE_* above)

#define OPTYPE_0   0x01
#define OPTYPE_1   0x02
#define OPTYPE_FF  0x03
//...
#define OPTYPE_CS  0x10
#define OPTYPE_DS  0x11
#define OPTYPE_ES  0x12
#define OPTYPE_FS  0x13
#define OPTYPE_GS  0x14
#define OPTYPE_SS  0x15
#define OPTYPE_CR0 0x16
#define OPTYPE_TSC 0x17 // time stamp counter
//...
#define OPTYPE_FLAGS  0x20
#define OPTYPE_xFLAGS 0x21 // RFLAGS/EFLAGS (depending on operand size)
#define OPTYPE_xCX_HI_xBX_LO 0x22 // represented by 2 registers CX:BX or ECX:EBX (depending on operand size)
#define OPTYPE_xDX_HI_xAX_LO 0x23 // DX:AX or EDX:EAX (depending on operand size)
#define OPTYPE_EDX_HI_EAX_LO 0x24 // DX:AX or EDX:EAX (depending on operand size)
#define OPTYPE_EDX_ECX_EBX_EAX 0x25 // all registers are set
//...
#define OPTYPE_STx 0x30
#define OPTYPE_ST0 0x31
#define OPTYPE_ST1 0x32
#define OPTYPE_FPU_STATUS  0x33
#define OPTYPE_FPU_CONTROL 0x34
#define OPTYPE_FPU_TAG 0x35
#define OPTYPE_FLDZ   0x36 // 0
#define OPTYPE_FLD1   0x37 // 1
#define OPTYPE_FLDPI  0x38 // pi
#define OPTYPE_FLDL2T 0x39 // lg 10
#define OPTYPE_FLDL2E 0x3A // lg e
#define OPTYPE_FLDLG2 0x3B // log_10 2
#define OPTYPE_FLDLN2 0x3C // log_e 2
//...
#define OPTYPE_CS_MSR 0x40
#define OPTYPE_EIP_MSR 0x41
#define OPTYPE_ESP_MSR 0x42
#define OPTYPE_KERNELBASE_MSR 0x43
#define OPTYPE_FMASK_MSR 0x44
#define OPTYPE_STAR_MSR 0x45
#define OPTYPE_CSTAR_MSR 0x46 // 32-bit mode
#define OPTYPE_LSTAR_MSR 0x47 // 64-bit mode


// NOTE: OPTYPES >= 0x80 reserved for registers (OP_REG+XX)
#define OPTYPE_REG_AL OP_REG+0x01
#define OPTYPE_REG_CL OP_REG+0x02
#define OPTYPE_REG_AH OP_REG+0x03
#define OPTYPE_REG_AX OP_REG+0x04
#define OPTYPE_REG_DX OP_REG+0x05
#define OPTYPE_REG_ECX OP_REG+0x06
#define OPTYPE_REG8 OP_REG+0x07

// If address size is 2, use BP
// If address size is 4, use EBP
// If address size is 8, use RBP
#define OPTYPE_REG_xBP OP_REG+0x08

// If address size is 2, use BP
// If address size is 4, use EBP
// If address size is 8, use RBP
#define OPTYPE_REG_xSP OP_REG+0x09

// If operand size is 2, take 8-bit register
// If operand size is 4, take 16-bit register
// If operand size is 8, take 32-bit register
#define OPTYPE_REG_xAX_SMALL OP_REG+0x0a

// If operand size is 2, take 16-bit register
// If operand size is 4, take 32-bit register
// If operand size is 8, take 64-bit register
#define OPTYPE_REG_xAX_BIG OP_REG+0x0b

typedef enum _CPU_TYPE
{
	CPU_UNKNOWN=0,

	///////////////////////////////////////
	// 1st generation
	///////////////////////////////////////
	// 1978
	//CPU_8086 = 1MB address limit, 16-bit registers
	// 1982
	//CPU_i186

	///////////////////////////////////////
	// 2nd generation
	///////////////////////////////////////
	// 1982
	//CPU_I286 // 16MB limit, 16-bit registers, added protected mode
	CPU_I287, // CPU_I286 + math coprocessor

	///////////////////////////////////////
	// 3rd generation
	///////////////////////////////////////
	// 1985
	CPU_I386, // 32-bit registers, 4GB memory limit
	// 1988
	CPU_I387, // CPU_I386 + math coprocessor

	///////////////////////////////////////
	// 4th generation (1989)
	///////////////////////////////////////
	CPU_I486,

	///////////////////////////////////////
	// 5th generation
	///////////////////////////////////////
	// 1993
	CPU_PENTIUM, // superscalar architecture
	// 1997
	//CPU_PENTIUM_MMX
	
	///////////////////////////////////////
	// 6th generation (1995)
	///////////////////////////////////////
	CPU_PENTIUM_PRO, // P6 architecture, no MMX, out-of-order execution, speculative execution
	//CPU_CYRIX_6X86,
	//CPU_AMD_K5 // RISC processor
	// 1997
	CPU_PENTIUM2, // Pentium Pro architecture + MMX
	//CPU_AMD_K6,
	//CPU_CYRIX_6X86MX, // Cyrix 6x86 + MMX
	// 1998
	CPU_AMD_K6_2, // added 3DNow! (MMX)
	// 1999
	// CPU_AMD_K6_3 // added SSE

	///////////////////////////////////////
	// 7th generation
	///////////////////////////////////////
	// 1999
	CPU_PENTIUM3, // introduced SSE
	// CPU_AMD_K7 // aka Athlon
	// 2000
	CPU_PENTIUM4, // introduced SSE2 and hyperthreading

	// 2004? 2005?
	CPU_PRESCOTT, // introduced SSE3

	///////////////////////////////////////
	// 8th generation (X86-64)
	// IA32 instruction set with 64-bit extensions, >4GB RAM
	///////////////////////////////////////

	// 2003
	CPU_AMD64, // includes Athlon 64 and Opteron aka X86-64

	// 2004?
	//CPU_EMD64 // Intel's version of AMD64
	CPU_IA64 // aka Itanium: new instruction set -- adds JMPE to IA32 mode to return to IA64 native code

} CPU_TYPE;

//////////////////////////////////////////////////////////////////
// Conditions (these can be OR'd)
//////////////////////////////////////////////////////////////////

// Used for Flags.Preconditions
#define COND_O   (1<<0)  // overflow (signed)
#define COND_C   (1<<1)  // below (unsigned)
#define COND_Z   (1<<2)  // equal (unsigned)
#define COND_S   (1<<3)  // sign set (signed)
#define COND_P   (1<<4)  // parity even
#define COND_BE  (1<<5)  // CF or ZF is set (unsigned)
#define COND_L   (1<<6)  // (SF && !OF) || (OF && !SF)
#define COND_LE  (1<<7)  // ZF || (SF && !OF) || (OF && !SF) (signed)
#define COND_NO  (1<<8)  // !O
#define COND_NC  (1<<9)  // !C (not below, above or equal to)
#define COND_NZ  (1<<10) // !Z (not equal)
#define COND_NS  (1<<11) // !S
#define COND_NP  (1<<12) // !P (parity odd)
#define COND_NL  (1<<13) // (!SF && !OF) || (SF && OF)
#define COND_G   (1<<14) // !ZF && ((!SF && !OF) || (SF && OF))
#define COND_D   (1<<15) // DF
#define COND_REG_xCX_BIG_Z  (1<<16) // CX/ECX/RCX (depending on address size) == 0
#define COND_REG_xCX_BIG_NZ (1<<17) // CX/ECX/RCX (depending on address size) != 0
#define COND_OP1_EQ_OP2 (1<<18)
#define COND_OP1_EQ_OP3 (1<<19)
#define COND_B   COND_C
#define COND_NAE COND_C
#define COND_E   COND_Z
#define COND_NA  COND_BE
#define COND_PE  COND_P
#define COND_U   COND_P
#define COND_NGE COND_L
#define COND_NG  COND_LE
#define COND_PO  COND_NP
#define COND_NU  COND_NP
#define COND_NE  COND_NZ
#define COND_NB  COND_NC
#define COND_AE  COND_NC
#define COND_NE  COND_NZ
#define COND_A   (COND_NC|COND_NZ)
#define COND_NBE COND_A
#define COND_GE COND_NL
#define COND_NLE COND_G

// Used for Opcode.FlagsChanged
#define FLAG_CF_SET (1<<0)
#define FLAG_DF_SET (1<<1)
#define FLAG_IF_SET (1<<2)
#define FLAG_SET_MASK (FLAG_CF_SET|FLAG_DF_SET|FLAG_IF_SET)

#define FLAG_SF_CLR (1<<3)
#define FLAG_ZF_CLR (1<<4)
#define FLAG_AF_CLR (1<<5)
#define FLAG_CF_CLR (1<<6)
#define FLAG_DF_CLR (1<<7)
#define FLAG_IF_CLR (1<<8)
#define FLAG_OF_CLR (1<<9)
#define FPU_C0_CLR (1<<19)
#define FPU_C1_CLR (1<<20)
#define FPU_C2_CLR (1<<21)
#define FPU_C3_CLR (1<<22)
#define FPU_ALL_CLR (FPU_C0_CLR|FPU_C1_CLR|FPU_C2_CLR|FPU_C3_CLR)
#define FLAG_CLR_MASK (FLAG_SF_CLR|FLAG_ZF_CLR|FLAG_AF_CLR|FLAG_CF_CLR|FLAG_DF_CLR|FLAG_IF_CLR|FLAG_OF_CLR|FPU_ALL_CLR)

#define FLAG_OF_MOD (1<<10)
#define FLAG_SF_MOD (1<<11)
#define FLAG_ZF_MOD (1<<12)
#define FLAG_AF_MOD (1<<13)
#define FLAG_PF_MOD (1<<14)
#define FLAG_CF_MOD (1<<15)
#define FLAG_DF_MOD (1<<16)
#define FLAG_IF_MOD (1<<17)
#define FLAG_ALL_MOD (FLAG_OF_MOD|FLAG_SF_MOD|FLAG_ZF_MOD|FLAG_AF_MOD|FLAG_PF_MOD|FLAG_CF_MOD|FLAG_DF_MOD|FLAG_IF_MOD)
#define FLAG_COMMON_MOD (FLAG_OF_MOD|FLAG_SF_MOD|FLAG_ZF_MOD|FLAG_AF_MOD|FLAG_PF_MOD|FLAG_CF_MOD)
#define FPU_C0_MOD (1<<23)
#define FPU_C1_MOD (1<<24)
#define FPU_C2_MOD (1<<25)
#define FPU_C3_MOD (1<<26)
#define FPU_ALL_MOD (FPU_C0_MOD|FPU_C1_MOD|FPU_C2_MOD|FPU_C3_MOD)
#define FLAG_MOD_MASK (FLAG_ALL_MOD|FPU_ALL_MOD)

#define FLAG_CF_TOG (1<<18)
#define FLAG_TOG_MASK FLAG_CF_TOG

// Used for Opcode.ResultsIfTrue and Opcode.ResultsIfFalse
#define OP1_DST         (1<<0)
#define OP2_DST         (1<<1)
#define OP3_DST         (1<<2)
#define OP1_SRC         (1<<3)
#define OP2_SRC         (1<<4)
#define OP3_SRC         (1<<5)
#define FPU_STACK_INC   (1<<6)
#define FPU_STACK_INC2  (1<<7)
#define FPU_STACK_DEC   (1<<8)
#define SERIALIZE_WRITE (1<<9)
#define SERIALIZE_READ  (1<<10)
#define xCX_DEC         (1<<11)
#define xCX_REP_DEC     (1<<12)
#define xDI_DEC         (1<<13)
#define xDI_INC         (1<<14)
#define xSI_DEC         (1<<15)
#define xSI_INC         (1<<16)
#define xDI_DECx        (1<<17)
#define xDI_INCx        (1<<18)
#define xSI_DECx        (1<<19)
#define xSI_INCx        (1<<20)
#define FPU_STACK_PUSH FPU_STACK_DEC
#define FPU_STACK_POP  FPU_STACK_INC
#define FPU_STACK_POP2 FPU_STACK_INC2
#define SERIALIZE_ALL (SERIALIZE_WRITE|SERIALIZE_READ)

#define X86_SEGMENT_OFFSET 0x00
#define X86_TEST_OFFSET    0x10
#define X86_CONTROL_OFFSET 0x20
#define X86_DEBUG_OFFSET   0x30
#define X86_FPU_OFFSET     0x40
#define X86_MMX_OFFSET     0x50
#define X86_XMM_OFFSET     0x60
#define X86_8BIT_OFFSET    0x70
#define X86_16BIT_OFFSET   0x80
#define X86_32BIT_OFFSET   0x90
#define AMD64_8BIT_OFFSET  0xA0
#define AMD64_16BIT_OFFSET 0xB0
#define AMD64_32BIT_OFFSET 0xC0
#define AMD64_64BIT_OFFSET 0xD0

typedef enum _X86_REGISTER
{
	// Segments
	X86_SEG_ES = X86_SEGMENT_OFFSET,
	X86_SEG_CS,
	X86_SEG_SS,
	X86_SEG_DS,
	X86_SEG_FS,
	X86_SEG_GS,

	// Miscellaneous
	X86_REG_FLAGS,
	X86_REG_EFLAGS,
	AMD64_REG_RFLAGS,
	X86_REG_IP,
	X86_REG_EIP,
	AMD64_REG_RIP,

	// Test registers
	X86_REG_TR0 = X86_TEST_OFFSET,
	X86_REG_TR1,
	X86_REG_TR2,
	X86_REG_TR3,
	X86_REG_TR4,
	X86_REG_TR5,
	X86_REG_TR6,
	X86_REG_TR7,
	X86_REG_TR8,
	X86_REG_TR9,
	X86_REG_TR10,
	X86_REG_TR11,
	X86_REG_TR12,
	X86_REG_TR13,
	X86_REG_TR14,
	X86_REG_TR15,

	// Control registers
	X86_REG_CR0=X86_CONTROL_OFFSET,
	X86_REG_CR1,
	X86_REG_CR2,
	X86_REG_CR3,
	X86_REG_CR4,
	X86_REG_CR5,
	X86_REG_CR6,
	X86_REG_CR7,
	X86_REG_CR8,
	X86_REG_CR9,
	X86_REG_CR10,
	X86_REG_CR11,
	X86_REG_CR12,
	X86_REG_CR13,
	X86_REG_CR14,
	X86_REG_CR15,

	// Debug registers
	X86_REG_DR0=X86_DEBUG_OFFSET,
	X86_REG_DR1,
	X86_REG_DR2,
	X86_REG_DR3,
	X86_REG_DR4,
	X86_REG_DR5,
	X86_REG_DR6,
	X86_REG_DR7,
	X86_REG_DR8,
	X86_REG_DR9,
	X86_REG_DR10,
	X86_REG_DR11,
	X86_REG_DR12,
	X86_REG_DR13,
	X86_REG_DR14,
	X86_REG_DR15,

	// FPU registers
	X86_REG_ST0=X86_FPU_OFFSET,
	X86_REG_ST1,
	X86_REG_ST2,
	X86_REG_ST3,
	X86_REG_ST4,
	X86_REG_ST5,
	X86_REG_ST6,
	X86_REG_ST7,

	// MMX registers
	X86_REG_MM0=X86_MMX_OFFSET,
	X86_REG_MM1,
	X86_REG_MM2,
	X86_REG_MM3,
	X86_REG_MM4,
	X86_REG_MM5,
	X86_REG_MM6,
	X86_REG_MM7,

	// XMM registers
	X86_REG_XMM0=X86_XMM_OFFSET,
	X86_REG_XMM1,
	X86_REG_XMM2,
	X86_REG_XMM3,
	X86_REG_XMM4,
	X86_REG_XMM5,
	X86_REG_XMM6,
	X86_REG_XMM7,

	// 8-bit registers
	X86_REG_AL=X86_8BIT_OFFSET,
	X86_REG_CL,
	X86_REG_DL,
	X86_REG_BL,
	X86_REG_AH,
	X86_REG_CH,
	X86_REG_DH,
	X86_REG_BH,

	// 16-bit registers
	X86_REG_AX=X86_16BIT_OFFSET,
	X86_REG_CX,
	X86_REG_DX,
	X86_REG_BX,
	X86_REG_SP,
	X86_REG_BP,
	X86_REG_SI,
	X86_REG_DI,

	// 32-bit registers
	X86_REG_EAX=X86_32BIT_OFFSET,
	X86_REG_ECX,
	X86_REG_EDX,
	X86_REG_EBX,
	X86_REG_ESP,
	X86_REG_EBP,
	X86_REG_ESI,
	X86_REG_EDI,

	// AMD64 8-bit registers
	AMD64_REG_AL=AMD64_8BIT_OFFSET,
	AMD64_REG_CL,
	AMD64_REG_DL,
	AMD64_REG_BL,
	AMD64_REG_SPL,
	AMD64_REG_BPL,
	AMD64_REG_SIL,
	AMD64_REG_DIL,
	AMD64_REG_R8B,
	AMD64_REG_R9B,
	AMD64_REG_R10B,
	AMD64_REG_R11B,
	AMD64_REG_R12B,
	AMD64_REG_R13B,
	AMD64_REG_R14B,
	AMD64_REG_R15B,

	// AMD64 16-bit registers
	AMD64_REG_AX=AMD64_16BIT_OFFSET,
	AMD64_REG_CX,
	AMD64_REG_DX,
	AMD64_REG_BX,
	AMD64_REG_SP,
	AMD64_REG_BP,
	AMD64_REG_SI,
	AMD64_REG_DI,
	AMD64_REG_R8W,
	AMD64_REG_R9W,
	AMD64_REG_R10W,
	AMD64_REG_R11W,
	AMD64_REG_R12W,
	AMD64_REG_R13W,
	AMD64_REG_R14W,
	AMD64_REG_R15W,

	// AMD64 32-bit registers
	AMD64_REG_EAX=AMD64_32BIT_OFFSET,
	AMD64_REG_ECX,
	AMD64_REG_EDX,
	AMD64_REG_EBX,
	AMD64_REG_ESP,
	AMD64_REG_EBP,
	AMD64_REG_ESI,
	AMD64_REG_EDI,
	AMD64_REG_R8D,
	AMD64_REG_R9D,
	AMD64_REG_R10D,
	AMD64_REG_R11D,
	AMD64_REG_R12D,
	AMD64_REG_R13D,
	AMD64_REG_R14D,
	AMD64_REG_R15D,

	// AMD64 64-bit registers
	AMD64_REG_RAX=AMD64_64BIT_OFFSET,
	AMD64_REG_RCX,
	AMD64_REG_RDX,
	AMD64_REG_RBX,
	AMD64_REG_RSP,
	AMD64_REG_RBP,
	AMD64_REG_RSI,
	AMD64_REG_RDI,
	AMD64_REG_R8,
	AMD64_REG_R9,
	AMD64_REG_R10,
	AMD64_REG_R11,
	AMD64_REG_R12,
	AMD64_REG_R13,
	AMD64_REG_R14,
	AMD64_REG_R15
} X86_REGISTER;

typedef enum _X86_TEST_REGISTER
{
	REG_TR0=0,
	REG_TR1,
	REG_TR2,
	REG_TR3,
	REG_TR4,
	REG_TR5,
	REG_TR6,
	REG_TR7,
	REG_TR8,
	REG_TR9,
	REG_TR10,
	REG_TR11,
	REG_TR12,
	REG_TR13,
	REG_TR14,
	REG_TR15
} X86_TEST_REGISTER;

typedef enum _X86_CONTROL_REGISTER
{
	REG_CR0,
	REG_CR1,
	REG_CR2,
	REG_CR3,
	REG_CR4,
	REG_CR5,
	REG_CR6,
	REG_CR7,
	REG_CR8,
	REG_CR9,
	REG_CR10,
	REG_CR11,
	REG_CR12,
	REG_CR13,
	REG_CR14,
	REG_CR15
} X86_CONTROL_REGISTER;

typedef enum _X86_DEBUG_REGISTER
{
	REG_DR0,
	REG_DR1,
	REG_DR2,
	REG_DR3,
	REG_DR4,
	REG_DR5,
	REG_DR6,
	REG_DR7,
	REG_DR8,
	REG_DR9,
	REG_DR10,
	REG_DR11,
	REG_DR12,
	REG_DR13,
	REG_DR14,
	REG_DR15
} X86_DEBUG_REGISTER;

typedef enum _X86_MMX_REGISTER
{
	REG_MM0=0,
	REG_MM1=1,
	REG_MM2=2,
	REG_MM3=3,
	REG_MM4=4,
	REG_MM5=5,
	REG_MM6=6,
	REG_MM7=7
} X86_MMX_REGISTER;

typedef enum _X86_SSE_REGISTER
{
	REG_XMM0=0,
	REG_XMM1=1,
	REG_XMM2=2,
	REG_XMM3=3,
	REG_XMM4=4,
	REG_XMM5=5,
	REG_XMM6=6,
	REG_XMM7=7
} X86_SSE_REGISTER;

typedef enum _X86_FPU_REGISTER
{
	REG_ST0=0,
	REG_ST1=1,
	REG_ST2=2,
	REG_ST3=3,
	REG_ST4=4,
	REG_ST5=5,
	REG_ST6=6,
	REG_ST7=7
} X86_FPU_REGISTER;

typedef enum _X86_8BIT_REGISTER
{
	REG_AL = 0,
	REG_CL = 1,
	REG_DL = 2,
	REG_BL = 3,
	REG_AH = 4,
	REG_CH = 5,
	REG_DH = 6,
	REG_BH = 7
} X86_8BIT_REGISTER;

typedef enum _X86_16BIT_REGISTER
{
	REG_AX = 0,
	REG_CX = 1,
	REG_DX = 2,
	REG_BX = 3,
	REG_SP = 4,
	REG_BP = 5,
	REG_SI = 6,
	REG_DI = 7
} X86_16BIT_REGISTER;

typedef enum _X86_32BIT_REGISTER
{
	REG_EAX = 0,
	REG_ECX = 1,
	REG_EDX = 2,
	REG_EBX = 3,
	REG_ESP = 4,
	REG_EBP = 5,
	REG_ESI = 6,
	REG_EDI = 7
} X86_32BIT_REGISTER;

typedef enum _X86_SEGMENT
{
	SEG_ES = 0,
	SEG_CS = 1,
	SEG_SS = 2,
	SEG_DS = 3,
	SEG_FS = 4,
	SEG_GS = 5,
	SEG_MAX = 6
} X86_SEGMENT;

extern char *X86_Registers[];

#pragma pack(push,1)
typedef struct _MODRM
{
	U8 mod : 2;
	U8 reg : 3;
	U8 rm : 3;
} MODRM;
typedef struct _SIB
{
	U8 scale : 2;
	U8 index : 3;
	U8 base : 3;
} SIB;
typedef struct _REX
{
	U8 unused : 4; // bits 4,5,6,7
	U8 w : 1; // bit 3
	U8 r : 1; // bit 2
	U8 x : 1; // bit 1
	U8 b : 1; // bit 0
} REX;
typedef struct _REX_MODRM
{
	U8 reg : 4;
	U8 rm : 4;
} REX_MODRM;
typedef struct _REX_SIB
{
	U8 index : 4;
	U8 base : 4;
} REX_SIB;
#pragma pack(pop)

//
// Properties:
// If an operand is OP_COND_EXEC, it means that it is executed only if the pre-conditions are met.
//
// If if an instruction has one or more OP_COND_DST operands, then the actions are determined by
// whether the Opcode.Preconditions are met or not. If all the COND_* flags in Opcode.Preconditions 
// are true, then the results are determined by ResultsIfTrue. If the preconditions are not met, then
// the results are determined by ResultsIfFalse.
//
// If Preconditions == NOCOND, then results in ResultsIfTrue are unconditional and ResultsIfFalse
// is ignored
//
typedef struct _X86_OPCODE
{
	struct _X86_OPCODE *Table;
	CPU_TYPE CPU; // minimum CPU (starting with i386)
	U32 MnemonicFlags;
	char Mnemonic[X86_MAX_INSTRUCTION_LEN+1];
	U32 OperandFlags[X86_MAX_OPERANDS];
	U32 Preconditions;
	U32 FlagsChanged; // changes in flags
	U32 ResultsIfTrue; // results if Preconditions are met
	U32 ResultsIfFalse; // results if Preconditions are not met
} X86_OPCODE;

typedef struct _X86_INSTRUCTION
{
	struct _INSTRUCTION *Instruction; // the generic instruction format representing this instruction

	X86_OPCODE Opcode;

	U8 sib_b;
	U8 modrm_b;
	MODRM modrm;
	SIB sib;
	U8 rex_b;
	REX rex;
	REX_MODRM rex_modrm;
	REX_SIB rex_sib;

	X86_SEGMENT DstSegment;
	union
	{
		X86_SEGMENT Segment;
		DWORD Selector;
	};

	// NOTE: these are for internal use, use Instruction->Operands[]
	//
	// If DstRegAddressing or SrcRegAddressing = TRUE then BaseRegister is the base register
	// It is the operand represented by SIBOperand
	//
	// The operand indices of the destination operands is in DstOpIndex[0 to DstOpCount-1]
	// The operand indices of the source operands is in SrcOpIndex[0 to SrcOpCount-1]
	//
	// These are used both for instructions like xadd/xchg (where both operands are source/destination)
	// and to represent implicit registers (e.g., cmpxchg)

	U8 SrcOpIndex[3];
	U8 DstOpIndex[3];

	// Addressing mode:
	// If DstRegAddressing = TRUE, then these apply to DstReg
	// If SrcRegAddressing = TRUE, then this applies to SrcReg[AddressIndex]
	// If both are false, then SrcReg and DstReg are not addresses
	X86_REGISTER BaseRegister;
	X86_REGISTER IndexRegister;
	
	U8 Scale;
	U8 HasDefault64Operand : 1;
	U8 HasOperandSizePrefix : 1;
	U8 HasAddressSizePrefix : 1;
	U8 HasSegmentOverridePrefix : 1;
	U8 HasLockPrefix : 1;
	U8 HasRepeatWhileEqualPrefix : 1;
	U8 HasRepeatWhileNotEqualPrefix : 1;
	U8 HasBranchTakenPrefix : 1;
	U8 HasBranchNotTakenPrefix : 1;
	U8 HasDstAddressing : 1;
	U8 HasSrcAddressing : 1; 
	U8 HasModRM : 1;
	U8 HasBaseRegister : 1;
	U8 HasIndexRegister : 1;
	U8 HasFullDisplacement : 1;
	U8 HasDstSegment : 1; // used for ins/cmps/scas/movs/etc which have 2 segments
	U8 DstAddressIndex : 2; // DstOpIndex[DstAddressIndex]
	U8 SrcAddressIndex : 2; // SrcOpIndex[SrcAddressIndex]
	U8 DstOpCount : 2;
	U8 SrcOpCount : 2;
	U8 OperandSize : 4;
	U8 AddressSize : 4;
	U8 Relative : 1;
	U8 HasSelector : 1; // segment is actually a selector
	U8 Group : 5;

	S64 Displacement;

} X86_INSTRUCTION;

////////////////////////////////////////////////////////////////////////////////////
// Exported functions
////////////////////////////////////////////////////////////////////////////////////

extern ARCHITECTURE_FORMAT_FUNCTIONS X86;

// Instruction setup
BOOL X86_InitInstruction(struct _INSTRUCTION *Instruction);
void X86_CloseInstruction(struct _INSTRUCTION *Instruction);

// Instruction translator
BOOL X86_TranslateInstruction(struct _INSTRUCTION *Instruction, BOOL Verbose);

// Instruction decoder
BOOL X86_GetInstruction(struct _INSTRUCTION *Instruction, U8 *Address, DWORD Flags);

// Function finding
U8 *X86_FindFunctionByPrologue(struct _INSTRUCTION *Instruction, U8 *StartAddress, U8 *EndAddress, DWORD Flags);

#ifdef __cplusplus
}
#endif
#endif // X86_DISASM_H

