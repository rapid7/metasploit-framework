
/*
 * libdasm -- simple x86 disassembly library
 * (c) 2004 - 2006  jt / nologin.org
 *
 * libdasm.c:
 * This file contains most code of libdasm. Check out
 * libdasm.h for function definitions.
 *
 */

#include <stdio.h>
#include <string.h>
#include "libdasm.h"
#include "opcode_tables.h"


// Endianess conversion routines (thanks Ero)

__inline__ BYTE FETCH8(BYTE *addr) {
	// So far byte cast seems to work on all tested platforms
	return *(BYTE *)addr;	
}

__inline__ WORD FETCH16(BYTE *addr) {
#if defined __X86__
	// Direct cast only for x86
	return *(WORD *)addr;
#else
	// Revert to memcpy
	WORD val;
	memcpy(&val, addr, 2);
#if defined __LITTLE_ENDIAN__
	return val;
#else
	return  ((val & 0xff00) >> 8) |
		((val & 0x00ff) << 8);

#endif // __LITTLE_ENDIAN__
#endif // __X86__
}

__inline__ DWORD FETCH32(BYTE *addr) {
#if defined __X86__
	return *(DWORD *)addr;	
#else
	DWORD val;
	memcpy(&val, addr, 4);
#if defined __LITTLE_ENDIAN__
	return val;
#else
	return  ((val & (0xff000000)) >> 24) |
		((val & (0x00ff0000)) >> 8)  |
		((val & (0x0000ff00)) << 8)  |
		((val & (0x000000ff)) << 24);

#endif // __LITTLE_ENDIAN__
#endif // __X86__
}

// Check for address/operand size override

__inline__ enum Mode MODE_CHECK_ADDR(enum Mode mode, int flags) {
	if (((mode == MODE_32) && (MASK_PREFIX_ADDR(flags) == 0)) ||
    	    ((mode == MODE_16) && (MASK_PREFIX_ADDR(flags) == 1)))
		return MODE_32;
	else 
		return MODE_16;
}
__inline__ enum Mode MODE_CHECK_OPERAND(enum Mode mode, int flags) {
	if (((mode == MODE_32) && (MASK_PREFIX_OPERAND(flags) == 0)) ||
    	    ((mode == MODE_16) && (MASK_PREFIX_OPERAND(flags) == 1)))
		return MODE_32;
	else 
		return MODE_16;
}


// Parse 2 and 3-byte opcodes

int get_real_instruction2(BYTE *addr, int *flags) {
	switch (*addr) {

		// opcode extensions for 2-byte opcodes
		case 0x00:
			// Clear extension
			*flags &= 0xffffff00;
			*flags |= EXT_G6;
			break;
		case 0x01:
			*flags &= 0xffffff00;
			*flags |= EXT_G7;
			break;
		case 0x71:
			*flags &= 0xffffff00;
			*flags |= EXT_GC;
			break;
		case 0x72:
			*flags &= 0xffffff00;
			*flags |= EXT_GD;
			break;
		case 0x73:
			*flags &= 0xffffff00;
			*flags |= EXT_GE;
			break;
		case 0xae:
			*flags &= 0xffffff00;
			*flags |= EXT_GF;
			break;
		case 0xba:
			*flags &= 0xffffff00;
			*flags |= EXT_G8;
			break;
		case 0xc7:
			*flags &= 0xffffff00;
			*flags |= EXT_G9;
			break;
		default:
			break;
	}
	return 0;
}

// Parse instruction flags, get opcode index

int get_real_instruction(BYTE *addr, int *index, int *flags) {
	switch (*addr) {

		// 2-byte opcode
		case 0x0f:
			*index += 1;
			*flags |= EXT_T2;
			break;

		// Prefix group 2
		case 0x2e:
			*index += 1;
			// Clear previous flags from same group (undefined effect)
			*flags &= 0xff00ffff;
			*flags |= PREFIX_CS_OVERRIDE;
			get_real_instruction(addr + 1, index, flags);
			break;
		case 0x36:
			*index += 1;
			*flags &= 0xff00ffff;
			*flags |= PREFIX_SS_OVERRIDE;
			get_real_instruction(addr + 1, index, flags);
			break;
		case 0x3e:
			*index += 1;
			*flags &= 0xff00ffff;
			*flags |= PREFIX_DS_OVERRIDE;
			get_real_instruction(addr + 1, index, flags);
			break;
		case 0x26:
			*index += 1;
			*flags &= 0xff00ffff;
			*flags |= PREFIX_ES_OVERRIDE;
			get_real_instruction(addr + 1, index, flags);
			break;
		case 0x64:
			*index += 1;
			*flags &= 0xff00ffff;
			*flags |= PREFIX_FS_OVERRIDE;
			get_real_instruction(addr + 1, index, flags);
			break;
		case 0x65:
			*index += 1;
			*flags &= 0xff00ffff;
			*flags |= PREFIX_GS_OVERRIDE;
			get_real_instruction(addr + 1, index, flags);
			break;
		// Prefix group 3 or 3-byte opcode
		case 0x66:
			// Do not clear flags from the same group!!!!
			*index += 1;
			*flags |= PREFIX_OPERAND_SIZE_OVERRIDE;
			get_real_instruction(addr + 1, index, flags); 
			break;
		// Prefix group 4
		case 0x67:
			// Do not clear flags from the same group!!!!
			*index += 1;
			*flags |=  PREFIX_ADDR_SIZE_OVERRIDE;
			get_real_instruction(addr + 1, index, flags); 
			break;

		// Extension group 1
		case 0x80:
			*flags |=  EXT_G1_1;
			break;
		case 0x81:
			*flags |=  EXT_G1_2;
			break;
		case 0x82:
			*flags |=  EXT_G1_1;
			break;
		case 0x83:
			*flags |=  EXT_G1_3;
			break;

		// Extension group 2
		case 0xc0:
			*flags |=  EXT_G2_1;
			break;
		case 0xc1:
			*flags |=  EXT_G2_2;
			break;
		case 0xd0:
			*flags |=  EXT_G2_3;
			break;
		case 0xd1:
			*flags |=  EXT_G2_4;
			break;
		case 0xd2:
			*flags |=  EXT_G2_5;
			break;
		case 0xd3:
			*flags |=  EXT_G2_6;
			break;

		// Escape to co-processor
		case 0xd8:
		case 0xd9:
		case 0xda:
		case 0xdb:
		case 0xdc:
		case 0xdd:
		case 0xde:
		case 0xdf:
			*index += 1;
			*flags |=  EXT_CP;
			break;

		// Prefix group 1 or 3-byte opcode
		case 0xf0:
			*index += 1;
			*flags &= 0x00ffffff;
			*flags |=  PREFIX_LOCK;
			get_real_instruction(addr + 1, index, flags); 
			break;
		case 0xf2:
			*index += 1;
			*flags &= 0x00ffffff;
			*flags |=  PREFIX_REPNE;
			get_real_instruction(addr + 1, index, flags); 
			break;
		case 0xf3:
			*index += 1;
			*flags &= 0x00ffffff;
			*flags |=  PREFIX_REP;
			get_real_instruction(addr + 1, index, flags); 
			break;

		// Extension group 3
		case 0xf6:
			*flags |=  EXT_G3_1;
			break;
		case 0xf7:
			*flags |=  EXT_G3_2;
			break;

		// Extension group 4
		case 0xfe:
			*flags |=  EXT_G4;
			break;

		// Extension group 5
		case 0xff:
			*flags |=  EXT_G5;
			break;
		default:
			break;
	}
	return 0;
}

// Parse operand and fill OPERAND structure

/*
 * This function is quite complex.. I'm not perfectly happy
 * with the logic yet. Anyway, the idea is to
 *
 * - check out modrm and sib
 * - based on modrm/sib and addressing method (AM_X),
 *   figure out the operand members and fill the struct
 *
 */
int get_operand(PINST inst, int oflags, PINSTRUCTION instruction,
	POPERAND op, BYTE *data, int offset, enum Mode mode, int iflags) {
	BYTE *addr = data + offset;
	int index = 0, sib = 0, scale = 0;
	int reg      = REG_NOP;
	int basereg  = REG_NOP;
	int indexreg = REG_NOP;
	int dispbytes = 0;
	enum Mode pmode;

	// Is this valid operand?
	if (oflags == FLAGS_NONE) {
		op->type = OPERAND_TYPE_NONE;
		return 1;
	}
	// Copy flags
	op->flags = oflags;

	// Set operand registers
	op->reg      = REG_NOP;
	op->basereg  = REG_NOP;
	op->indexreg = REG_NOP;

	// Offsets
	op->dispoffset = 0;
	op->immoffset  = 0;

	// Parse modrm and sib
	if (inst->modrm) {
		pmode = MODE_CHECK_ADDR(mode, iflags);

		// Update length only once!
		if (!instruction->length) {
			instruction->modrm = *addr;
			instruction->length += 1;
		}
		// Register
		reg =  MASK_MODRM_REG(*addr);

		// Displacement bytes
		// SIB can also specify additional displacement, see below
		if (MASK_MODRM_MOD(*addr) == 0) {
			if ((pmode == MODE_32) && (MASK_MODRM_RM(*addr) == REG_EBP))
				dispbytes = 4;
			if ((pmode == MODE_16) && (MASK_MODRM_RM(*addr) == REG_ESI))
				dispbytes = 2;
		} else if (MASK_MODRM_MOD(*addr) == 1) {
			dispbytes = 1;

		} else if (MASK_MODRM_MOD(*addr) == 2) {
			dispbytes = (pmode == MODE_32) ? 4 : 2; 
		}
		// Base and index registers

		// 32-bit mode
		if (pmode == MODE_32) {
			if ((MASK_MODRM_RM(*addr) == REG_ESP) && 
					(MASK_MODRM_MOD(*addr) != 3)) {
				sib = 1;
				instruction->sib = *(addr + 1);

				// Update length only once!
				if (instruction->length == 1) {
					instruction->sib = *(addr + 1);
					instruction->length += 1;
				}
				basereg  = MASK_SIB_BASE( *(addr + 1));
				indexreg = MASK_SIB_INDEX(*(addr + 1));
				scale    = MASK_SIB_SCALE(*(addr + 1)) * 2;
				// Fix scale *8
				if (scale == 6)
					scale += 2;

				// Special case where base=ebp and MOD = 0
				if ((basereg == REG_EBP) && !MASK_MODRM_MOD(*addr)) {
					basereg = REG_NOP;
						dispbytes = 4;
				}
				if (indexreg == REG_ESP)
					indexreg = REG_NOP;
			} else {
				if (!MASK_MODRM_MOD(*addr) && (MASK_MODRM_RM(*addr) == REG_EBP))
					basereg = REG_NOP;
				else
					basereg = MASK_MODRM_RM(*addr);
			}
		// 16-bit
		} else {
			switch (MASK_MODRM_RM(*addr)) {
				case 0:
					basereg  = REG_EBX;
					indexreg = REG_ESI;
					break;
				case 1:
					basereg  = REG_EBX;
					indexreg = REG_EDI;
					break;
				case 2:
					basereg  = REG_EBP;
					indexreg = REG_ESI;
					break;
				case 3:
					basereg  = REG_EBP;
					indexreg = REG_EDI;
					break;
				case 4:
					basereg  = REG_ESI;
					indexreg = REG_NOP;
					break;
				case 5:
					basereg  = REG_EDI;
					indexreg = REG_NOP;
					break;
				case 6:
					if (!MASK_MODRM_MOD(*addr))
						basereg = REG_NOP;
					else
						basereg = REG_EBP;
					indexreg = REG_NOP;
					break;
				case 7:
					basereg  = REG_EBX;
					indexreg = REG_NOP;
					break;
			}
			if (MASK_MODRM_MOD(*addr) == 3) {
				basereg  = MASK_MODRM_RM(*addr);
				indexreg = REG_NOP;
			}
		}
	}

	// Operand addressing method -specific parsing
	switch (MASK_AM(oflags)) {

		// Register encoded in instruction
		case AM_REG:
			op->type = OPERAND_TYPE_REGISTER;
			op->reg  = MASK_REG(oflags);
			break;

		// Register indirect encoded in instruction
		case AM_IND:
			op->type    = OPERAND_TYPE_MEMORY;
			op->basereg = MASK_REG(oflags);
			break;

		// Register/memory encoded in MODRM
		case AM_M:
			if (MASK_MODRM_MOD(*addr) == 3)
				return 0;
			goto skip_rest;
		case AM_R:
			if (MASK_MODRM_MOD(*addr) != 3)
				return 0;
skip_rest:
		case AM_Q:
		case AM_W:
		case AM_E:
			op->type = OPERAND_TYPE_MEMORY;
			op->dispbytes          = dispbytes;
			instruction->dispbytes = dispbytes;
			op->basereg            = basereg;
			op->indexreg           = indexreg;
			op->scale              = scale;

			index = (sib) ? 1 : 0;
			if (dispbytes)
				op->dispoffset = index + 1 + offset;
			switch (dispbytes) {
				case 0:
					break;
				case 1:
					op->displacement = FETCH8(addr + 1 + index);
					// Always sign-extend
					if (op->displacement >= 0x80)
						op->displacement |= 0xffffff00;
					break;
				case 2:
					op->displacement = FETCH16(addr + 1 + index);
					break;
				case 4:
					op->displacement = FETCH32(addr + 1 + index);
					break;
			}

			// MODRM defines register
			if ((basereg != REG_NOP) && (MASK_MODRM_MOD(*addr) == 3)) { 
				op->type = OPERAND_TYPE_REGISTER;
				op->reg  = basereg;
			}
			break;

		// Immediate byte 1 encoded in instruction
		case AM_I1:
			op->type = OPERAND_TYPE_IMMEDIATE;
			op->immbytes  = 1;
			op->immediate = 1;
			break;
		// Immediate value
		case AM_J:
			op->type = OPERAND_TYPE_IMMEDIATE;
			// Always sign-extend
			oflags |= F_s;
		case AM_I:
			op->type = OPERAND_TYPE_IMMEDIATE;
			index  = (inst->modrm) ? 1 : 0;
			index += (sib) ? 1 : 0;
			index += instruction->immbytes;
			index += instruction->dispbytes;
			op->immoffset = index + offset;

			// check mode
			mode = MODE_CHECK_OPERAND(mode, iflags);

			switch (MASK_OT(oflags)) {
				case OT_b:
					op->immbytes  = 1;
					op->immediate = FETCH8(addr + index);
					if ((op->immediate >= 0x80) &&
						(MASK_FLAGS(oflags) == F_s))
						op->immediate |= 0xffffff00;
					break;
				case OT_v:
					op->immbytes  = (mode == MODE_32) ?
						4 : 2;
					op->immediate = (mode == MODE_32) ?
						FETCH32(addr + index) :
						FETCH16(addr + index);
					break;
				case OT_w:
					op->immbytes  = 2;
					op->immediate =	FETCH16(addr + index);
					break;
			}
			instruction->immbytes += op->immbytes;
			break;

		// 32-bit or 48-bit address
		case AM_A:
			op->type = OPERAND_TYPE_IMMEDIATE;
			// check mode
			mode = MODE_CHECK_OPERAND(mode, iflags);

			op->dispbytes    = (mode == MODE_32) ? 6 : 4;
			op->displacement = (mode == MODE_32) ?
				FETCH32(addr) : FETCH16(addr);
			op->section = FETCH16(addr + op->dispbytes - 2);

			instruction->dispbytes    = op->dispbytes;
			instruction->sectionbytes = 2;
			break;

		// Plain displacement without MODRM/SIB
		case AM_O:
			op->type = OPERAND_TYPE_MEMORY;
			switch (MASK_OT(oflags)) {
				case OT_b:
					op->dispbytes    = 1;
					op->displacement = FETCH8(addr);
					break;
				case OT_v:
					op->dispbytes    = (mode == MODE_32) ? 4 : 2;
					op->displacement = (mode == MODE_32) ?
						FETCH32(addr) : FETCH16(addr);
					break;
			}
			instruction->dispbytes = op->dispbytes;
			op->dispoffset = offset;
			break;

		// General-purpose register encoded in MODRM
		case AM_G:
			op->type = OPERAND_TYPE_REGISTER;
			op->reg  = reg;
			break;

		// control register encoded in MODRM
		case AM_C:
		// debug register encoded in MODRM
		case AM_D:
		// Segment register encoded in MODRM
		case AM_S:
		// TEST register encoded in MODRM
		case AM_T:
		// MMX register encoded in MODRM
		case AM_P:
		// XMM register encoded in MODRM
		case AM_V:
			op->type = OPERAND_TYPE_REGISTER;
			op->reg  = MASK_MODRM_REG(instruction->modrm);
			break;
	}
	return 1;
}


// Print operand string

#if !defined NOSTR
int get_operand_string(INSTRUCTION *inst, OPERAND *op,
	enum Format format, DWORD offset, char *string, int length) {
	
	enum Mode mode;
	int regtype = 0;
	DWORD tmp = 0;

	memset(string, 0, length);

	if (op->type == OPERAND_TYPE_REGISTER) {
		// check mode
		mode = MODE_CHECK_OPERAND(inst->mode, inst->flags);

		if (format == FORMAT_ATT)
			snprintf(string + strlen(string), length - strlen(string), "%%");
	
		// Determine register type
		switch (MASK_AM(op->flags)) {
			case AM_REG:
				if (MASK_FLAGS(op->flags) == F_r)
					regtype = REG_SEGMENT;
				else if (MASK_FLAGS(op->flags) == F_f)
					regtype = REG_FPU;
				else
					regtype = REG_GEN_DWORD;
				break;
			case AM_E:
			case AM_G:
			case AM_R:
				regtype = REG_GEN_DWORD;
				break;
			// control register encoded in MODRM
			case AM_C:
				regtype = REG_CONTROL;
				break;
			// debug register encoded in MODRM
			case AM_D:
				regtype = REG_DEBUG;
				break;
			// Segment register encoded in MODRM
			case AM_S:
				regtype = REG_SEGMENT;
				break;
			// TEST register encoded in MODRM
			case AM_T:
				regtype = REG_TEST;
				break;
			// MMX register encoded in MODRM
			case AM_P:
			case AM_Q:
				regtype = REG_MMX;
				break;
			// XMM register encoded in MODRM
			case AM_V:
			case AM_W:
				regtype = REG_XMM;
				break;
		}
		if (regtype == REG_GEN_DWORD) {
			 switch (MASK_OT(op->flags)) {
				case OT_b:
					snprintf(string + strlen(string), length - strlen(string),
						"%s", reg_table[REG_GEN_BYTE][op->reg]);
                                        break;
				case OT_v:
					snprintf(string + strlen(string), length - strlen(string),
						"%s", (mode == MODE_32) ?
						reg_table[REG_GEN_DWORD][op->reg] :
						reg_table[REG_GEN_WORD][op->reg]);
                                        break;
				case OT_w:
					snprintf(string + strlen(string), length - strlen(string),
						"%s", reg_table[REG_GEN_WORD][op->reg]);
					break;
				case OT_d:
					snprintf(string + strlen(string), length - strlen(string),
						"%s", reg_table[REG_GEN_DWORD][op->reg]);
					break;
			}
		} else
			snprintf(string + strlen(string), length - strlen(string),
				"%s", reg_table[regtype][op->reg]);

	} else if (op->type == OPERAND_TYPE_MEMORY) {
		// check mode
		mode = MODE_CHECK_ADDR(inst->mode, inst->flags);

		// Operand-specific segment override 
		if (MASK_PREFIX_G2(inst->flags))
			snprintf(string + strlen(string),
				length - strlen(string),
				"%s%s:", (format == FORMAT_ATT) ? "%" : "", 
				reg_table[REG_SEGMENT][(MASK_PREFIX_G2(inst->flags)) - 1]);
		// Some ATT stuff we need to check at this point
		if (format == FORMAT_ATT) {

			// "executable" operand
			if (MASK_PERMS(op->flags) == P_x)
				snprintf(string + strlen(string),
					length - strlen(string), "*");

			// displacement in front of brackets
			if (op->dispbytes)
				snprintf(string + strlen(string),
					length - strlen(string),
					"0x%x", op->displacement); 

			// no empty brackets - we're ready
			if ((op->basereg  == REG_NOP) &&
			    (op->indexreg == REG_NOP))
				return 1;
		}
		// Open memory addressing brackets
		snprintf(string + strlen(string), length - strlen(string),
			"%s", (format == FORMAT_ATT) ? "(" : "["); 

		// Base register
		if (op->basereg != REG_NOP) {
			snprintf(string + strlen(string), length - strlen(string),
				"%s%s", (format == FORMAT_ATT) ? "%" : "", 
				(mode == MODE_32) ?
				reg_table[REG_GEN_DWORD][op->basereg] :
				reg_table[REG_GEN_WORD][op->basereg]);
		}
		// Index register
		if (op->indexreg != REG_NOP) {
			if (op->basereg != REG_NOP)
				snprintf(string + strlen(string), length - strlen(string),
					"%s%s", (format == FORMAT_ATT) ? ",%" : "+", 
					(mode == MODE_32) ?
					reg_table[REG_GEN_DWORD][op->indexreg] :
					reg_table[REG_GEN_WORD][op->indexreg]); 
			else
				snprintf(string + strlen(string), length - strlen(string),
					"%s%s", (format == FORMAT_ATT) ? "%" : "",
					(mode == MODE_32) ?
					reg_table[REG_GEN_DWORD][op->indexreg] :
					reg_table[REG_GEN_WORD][op->indexreg]); 
			switch (op->scale) {
				case 2:
					snprintf(string + strlen(string), length - strlen(string),
						"%s", (format == FORMAT_ATT) ?
						",2" : "*2"); 
					break;
				case 4:
					snprintf(string + strlen(string), length - strlen(string),
						"%s", (format == FORMAT_ATT) ?
						",4" : "*4"); 
					break;
				case 8:
					snprintf(string + strlen(string), length - strlen(string),
						"%s", (format == FORMAT_ATT) ?
						",8" : "*8"); 
					break;
			}
		}
		// INTEL displacement
		if (inst->dispbytes && (format != FORMAT_ATT)) {
			if ((op->basereg != REG_NOP) || (op->indexreg != REG_NOP)) {
				// Negative displacement
				if (op->displacement & (1<<(op->dispbytes*8-1))) {
					tmp = op->displacement;
					switch (op->dispbytes) {
						case 1:
							tmp = ~tmp & 0xff;
							break;
						case 2:
							tmp = ~tmp & 0xffff;
							break;
						case 4:
							tmp = ~tmp;
							break;
					}
					snprintf(string + strlen(string),
						length - strlen(string),
						"-0x%x", tmp + 1);
				// Positive displacement
				} else
					snprintf(string + strlen(string),
						length - strlen(string),
						"+0x%x", op->displacement);
			// Plain displacement
			} else {
				snprintf(string + strlen(string),
					length - strlen(string),
					"0x%x", op->displacement);
			}
		}
		// Close memory addressing brackets
		snprintf(string + strlen(string), length - strlen(string),
				"%s", (format == FORMAT_ATT) ? ")" : "]"); 

	} else if (op->type == OPERAND_TYPE_IMMEDIATE) {

		switch (MASK_AM(op->flags)) {
			case AM_J:
				snprintf(string + strlen(string), length - strlen(string),
					"0x%x", op->immediate + inst->length + offset);
				break;
			case AM_I1:
			case AM_I:
				if (format == FORMAT_ATT)
					snprintf(string + strlen(string), length - strlen(string), "$");
				snprintf(string + strlen(string), length - strlen(string),
					"0x%x", op->immediate);
				break;
			// 32-bit or 48-bit address
			case AM_A:
				snprintf(string + strlen(string), length - strlen(string),
					"%s0x%x:%s0x%x",
					(format == FORMAT_ATT) ? "$" : "",
					op->section, 
					(format == FORMAT_ATT) ? "$" : "",
					op->displacement);
				break;
		}

	} else
		return 0;

	return 1;
}

#endif


// Fetch instruction

/*
 * The operation is quite straightforward:
 *
 * - determine actual opcode (skip prefixes etc.)
 * - figure out which instruction table to use
 * - index the table with opcode
 * - parse operands
 * - fill instruction structure
 *
 * Only point where this gets hairy is those *brilliant*
 * opcode extensions....
 *
 */
int get_instruction(PINSTRUCTION inst, BYTE *addr, enum Mode mode) {
	PINST ptr = NULL;
	int index = 0;
	int flags = 0;

	memset(inst, 0, sizeof(INSTRUCTION));

	// Parse flags, skip prefixes etc.
	get_real_instruction(addr, &index, &flags);

	// Select instruction table 

	// No extensions - normal 1-byte opcode:
	if (MASK_EXT(flags) == 0) {
		inst->opcode = *(addr + index);
		ptr = &inst_table1[inst->opcode];

	// FPU opcodes
	} else if (MASK_EXT(flags) == EXT_CP) {
		if (*(addr + index) < 0xc0) {
			// MODRM byte adds the additional byte
			index--;
			inst->fpuindex = *(addr + index) - 0xd8;
			inst->opcode   = *(addr + index + 1);
			ptr = &inst_table4[inst->fpuindex]
				[MASK_MODRM_REG(inst->opcode)];
		} else {
			inst->fpuindex = *(addr + index - 1) - 0xd8;
			inst->opcode   = *(addr + index);
			ptr = &inst_table4[inst->fpuindex]
				[inst->opcode - 0xb8];
		}
	// 2 or 3-byte opcodes
	} else if (MASK_EXT(flags) == EXT_T2) {
		inst->opcode = *(addr + index);

		// Parse flags, skip prefixes etc. (again)
		get_real_instruction2(addr + index, &flags);

		// 2-byte opcode table
		ptr = &inst_table2[inst->opcode];

		// 3-byte opcode tables
		if (MASK_TYPE_FLAGS(ptr->type) == TYPE_3) {
			// prefix 0x66
			if (MASK_PREFIX_OPERAND(flags) == 1) {
				ptr = &inst_table3_66[inst->opcode];

			// prefix 0xf2
			} else if (MASK_PREFIX_G1(flags) == 2) {
				ptr = &inst_table3_f2[inst->opcode];

			// prefix 0xf3
			} else if (MASK_PREFIX_G1(flags) == 3) {
				ptr = &inst_table3_f3[inst->opcode];

			}
		}
	}
	// Opcode extension tables
	if (MASK_EXT(flags) && (MASK_EXT(flags) < EXT_T2)) {
		inst->opcode   = *(addr + index);
		inst->extindex = MASK_MODRM_REG(*(addr + index + 1));

		switch (MASK_EXT(flags)) {
			case EXT_GC:
				// prefix 0x66
				if (MASK_PREFIX_OPERAND(flags) == 1)
					ptr = &inst_table_ext12_66[inst->extindex];
				else
					ptr = &inst_table_ext12[inst->extindex];
				break;
			case EXT_GD:	
				// prefix 0x66
				if (MASK_PREFIX_OPERAND(flags) == 1)
					ptr = &inst_table_ext13_66[inst->extindex];
				else
					ptr = &inst_table_ext13[inst->extindex];
				break;
			case EXT_GE:	
				// prefix 0x66
				if (MASK_PREFIX_OPERAND(flags) == 1)
					ptr = &inst_table_ext14_66[inst->extindex];
				else
					ptr = &inst_table_ext14[inst->extindex];
				break;
			// monitor/mwait
			// XXX: hack.....
			case EXT_G7:	
				if (MASK_MODRM_MOD(*(addr + index + 1)) == 3) {
					if (inst->extindex != 1)
						return 0;
					if (MASK_MODRM_RM(*(addr + index + 1)) == 0) {
						ptr = &inst_monitor;
						// index is incremented to get
						// correct instruction len
						index++;
					} else if (MASK_MODRM_RM(*(addr + index + 1)) == 1) {
						ptr = &inst_mwait;
						index++;
					} else
						return 0;

				} else {
					ptr = &inst_table_ext7[inst->extindex];
				}
				break;
			default:
				ptr = &inst_table_ext[(MASK_EXT(flags)) - 1]
					[inst->extindex];
				break;
		}
	}
	// Index points now to first byte after prefixes/escapes
	index++;

	// Illegal instruction
	if (!ptr)
		return 0;
        if (!ptr->mnemonic)
		return 0;

	// Copy instruction type
	inst->type = MASK_TYPE_VALUE(ptr->type);

	// Pointer to instruction table
	inst->ptr = ptr;

	// Parse operands
	if (!get_operand(ptr, ptr->flags1, inst, &inst->op1, addr, index,
			mode, flags))
		return 0;
	if (!get_operand(ptr, ptr->flags2, inst, &inst->op2, addr, index,
			mode, flags))
		return 0;
	if (!get_operand(ptr, ptr->flags3, inst, &inst->op3, addr, index,
			mode, flags))
		return 0;

	// Add modrm/sib, displacement and immediate bytes in size
	inst->length += index + inst->immbytes + inst->dispbytes;

	// Copy addressing mode
	inst->mode = mode;

	// Copy instruction flags
	inst->flags = flags;

	return inst->length;
}


// Print instruction mnemonic

#if !defined NOSTR
int get_mnemonic_string(INSTRUCTION *inst, enum Format format, char *string, int length) {
	int mode;

	memset(string, 0, length);

	// Segment override, branch hint
	if (MASK_PREFIX_G2(inst->flags) &&
		(inst->op1.type != OPERAND_TYPE_MEMORY) &&
		(inst->op2.type != OPERAND_TYPE_MEMORY))  {
		// Branch hint
		if (inst->type == INSTRUCTION_TYPE_JMPC)
			snprintf(string + strlen(string), length - strlen(string),
				"%s ", reg_table[REG_BRANCH][(MASK_PREFIX_G2(inst->flags)) - 1]);
		// Segment override for others
		else
			snprintf(string + strlen(string), length - strlen(string),
				"%s ", reg_table[REG_SEGMENT][(MASK_PREFIX_G2(inst->flags)) - 1]);
	}

	// Rep, lock etc.
	if (MASK_PREFIX_G1(inst->flags) &&
			(MASK_EXT(inst->flags) != EXT_T2))
		snprintf(string + strlen(string), length - strlen(string),
			"%s", rep_table[(MASK_PREFIX_G1(inst->flags)) - 1]);

	// Mnemonic
	// XXX: quick hack for jcxz/jecxz.. check if there are more
	// of these opcodes that have different mnemonic in same opcode
	if (((inst->type == INSTRUCTION_TYPE_JMPC) &&
			(inst->opcode == 0xe3)) &&
			(MASK_PREFIX_ADDR(inst->flags) == 1))
		snprintf(string + strlen(string), length - strlen(string),
			"jcxz");
	else
		snprintf(string + strlen(string), length - strlen(string),
			"%s", inst->ptr->mnemonic);


	// memory operation size in push/pop:
	if (inst->type == INSTRUCTION_TYPE_PUSH) {
		if (inst->op1.type == OPERAND_TYPE_IMMEDIATE) {
			switch (inst->op1.immbytes) {
				case 1:
					snprintf(string + strlen(string),
						length - strlen(string),
						"%s", (format == FORMAT_ATT) ?
						"b" : " byte");
					break;
				case 2:
					snprintf(string + strlen(string),
						length - strlen(string),
						"%s", (format == FORMAT_ATT) ?
						"w" : " word");
					break;
				case 4:
					snprintf(string + strlen(string),
						length - strlen(string),
						"%s", (format == FORMAT_ATT) ?
						"l" : " dword");
					break;
			}

		} else if (inst->op1.type == OPERAND_TYPE_MEMORY) {
			mode = MODE_CHECK_OPERAND(inst->mode, inst->flags);

			if (mode == MODE_16) {
				snprintf(string + strlen(string),
					length - strlen(string),
					"%s", (format == FORMAT_ATT) ?
					"w" : " word");
			} else if (mode == MODE_32) {
				snprintf(string + strlen(string),
					length - strlen(string),
					"%s", (format == FORMAT_ATT) ?
					"l" : " dword");
			}

		}
		return 1;

	}
	if (inst->type == INSTRUCTION_TYPE_POP) {
		if (inst->op1.type == OPERAND_TYPE_MEMORY) {
			mode = MODE_CHECK_OPERAND(inst->mode, inst->flags);

			if (mode == MODE_16) {
				snprintf(string + strlen(string),
					length - strlen(string),
					"%s", (format == FORMAT_ATT) ?
					"w" : " word");
			} else if (mode == MODE_32) {
				snprintf(string + strlen(string),
					length - strlen(string),
					"%s", (format == FORMAT_ATT) ?
					"l" : " dword");
			}
		}
		return 1;
	}

	// memory operation size in immediate to memory operations
	if (inst->ptr->modrm && (MASK_MODRM_MOD(inst->modrm) != 3) &&
		(MASK_AM(inst->op2.flags) == AM_I)) {

		switch (MASK_OT(inst->op1.flags)) {
			case OT_b:
				snprintf(string + strlen(string), length - strlen(string),
					"%s", (format == FORMAT_ATT) ?
					"b" : " byte");
				break;
			case OT_w:
				snprintf(string + strlen(string), length - strlen(string),
					"%s", (format == FORMAT_ATT) ?
					"w" : " word");
				break;
			case OT_d:
				snprintf(string + strlen(string), length - strlen(string),
					"%s", (format == FORMAT_ATT) ?
					"l" : " dword");
				break;
			case OT_v:
				if (((inst->mode == MODE_32) && (MASK_PREFIX_OPERAND(inst->flags) == 0)) ||
				    ((inst->mode == MODE_16) && (MASK_PREFIX_OPERAND(inst->flags) == 1)))
					snprintf(string + strlen(string), length - strlen(string),
						"%s", (format == FORMAT_ATT) ?
						"l" : " dword");
				else
					snprintf(string + strlen(string), length - strlen(string),
						"%s", (format == FORMAT_ATT) ?
						"w" : " word");
				break;
		}
	}

	// XXX: there might be some other cases where size is needed..

	return 1;
}

// Print operands

int get_operands_string(INSTRUCTION *inst, enum Format format, DWORD offset,
	char *string, int length) {

	if (format == FORMAT_ATT) {
		if (inst->op3.type != OPERAND_TYPE_NONE) {
			get_operand_string(inst, &inst->op3, format, offset,
				string + strlen(string), length - strlen(string));
			snprintf(string + strlen(string), length - strlen(string), ",");
		}
		if (inst->op2.type != OPERAND_TYPE_NONE) {
			get_operand_string(inst, &inst->op2, format, offset,
				string + strlen(string), length - strlen(string));
			snprintf(string + strlen(string), length - strlen(string), ",");
		}
		if (inst->op1.type != OPERAND_TYPE_NONE)
			get_operand_string(inst, &inst->op1, format, offset,
				string + strlen(string), length - strlen(string));
	} else if (format == FORMAT_INTEL) {
		if (inst->op1.type != OPERAND_TYPE_NONE)
			get_operand_string(inst, &inst->op1, format, offset,
				string + strlen(string), length - strlen(string));
		if (inst->op2.type != OPERAND_TYPE_NONE) {
			snprintf(string + strlen(string), length - strlen(string), ",");
			get_operand_string(inst, &inst->op2, format, offset,
				string + strlen(string), length - strlen(string));
		}
		if (inst->op3.type != OPERAND_TYPE_NONE) {
			snprintf(string + strlen(string), length - strlen(string), ",");
			get_operand_string(inst, &inst->op3, format, offset,
				string + strlen(string), length - strlen(string));
		}
	} else
		return 0;

	return 1;
}

// Print instruction mnemonic, prefixes and operands

int get_instruction_string(INSTRUCTION *inst, enum Format format, DWORD offset,
		char *string, int length) {

	// Print the actual instruction string with possible prefixes etc.
	get_mnemonic_string(inst, format, string, length);

	snprintf(string + strlen(string), length - strlen(string), " ");
	
	// Print operands
	if (!get_operands_string(inst, format, offset,
		string + strlen(string), length - strlen(string)))
		return 0;

	return 1;
}

#endif

// Helper functions

int get_register_type(POPERAND op) {
	
	if (op->type != OPERAND_TYPE_REGISTER)
		return 0;
	switch (MASK_AM(op->flags)) {
		case AM_REG:
			if (MASK_FLAGS(op->flags) == F_r)
				return REGISTER_TYPE_SEGMENT;
			else if (MASK_FLAGS(op->flags) == F_f)
				return REGISTER_TYPE_FPU;
			else
				return REGISTER_TYPE_GEN;
		case AM_E:
		case AM_G:
		case AM_R:
				return REGISTER_TYPE_GEN;
		case AM_C:
				return REGISTER_TYPE_CONTROL;
		case AM_D:
				return REGISTER_TYPE_DEBUG;
		case AM_S:
				return REGISTER_TYPE_SEGMENT;
		case AM_T:
				return REGISTER_TYPE_TEST;
		case AM_P:
		case AM_Q:
				return REGISTER_TYPE_MMX;
		case AM_V:
		case AM_W:
				return REGISTER_TYPE_XMM;
		default:
				break;
	}
	return 0;
}

int get_operand_type(POPERAND op) {
	return op->type;
}

int get_operand_register(POPERAND op) {
	return op->reg;
}

int get_operand_basereg(POPERAND op) {
	return op->basereg;
}

int get_operand_indexreg(POPERAND op) {
	return op->indexreg;
}

int get_operand_scale(POPERAND op) {
	return op->scale;
}

int get_operand_immediate(POPERAND op, DWORD *imm) {
	if (op->immbytes) {
		*imm = op->immediate;
		return 1;
	} else
		return 0;
}

int get_operand_displacement(POPERAND op, DWORD *disp) {
	if (op->dispbytes) {
		*disp = op->displacement;
		return 1;
	} else
		return 0;
}

// XXX: note that source and destination are not always literal

POPERAND get_source_operand(PINSTRUCTION inst) {
	if (inst->op2.type != OPERAND_TYPE_NONE)
		return &inst->op2;
	else
		return NULL;
}
POPERAND get_destination_operand(PINSTRUCTION inst) {
	if (inst->op1.type != OPERAND_TYPE_NONE)
		return &inst->op1;
	else
		return NULL;
}


