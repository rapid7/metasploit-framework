/****************************************************************************
 ****************************************************************************
 ***
 ***   This header was automatically generated from a Linux kernel header
 ***   of the same name, to make information necessary for userspace to
 ***   call into the kernel available to libc.  It contains only constants,
 ***   structures, and macros generated from the original header, and thus,
 ***   contains no copyrightable information.
 ***
 ****************************************************************************
 ****************************************************************************/
#ifndef _I386_ALTERNATIVE_H
#define _I386_ALTERNATIVE_H

#include <asm/types.h>
#include <linux/stddef.h>
#include <linux/types.h>

struct alt_instr {
 u8 *instr;
 u8 *replacement;
 u8 cpuid;
 u8 instrlen;
 u8 replacementlen;
 u8 pad;
};

struct module;
#define alternative(oldinstr, newinstr, feature)   asm volatile ("661:\n\t" oldinstr "\n662:\n"   ".section .altinstructions,\"a\"\n"   "  .align 4\n"   "  .long 661b\n"     "  .long 663f\n"     "  .byte %c0\n"     "  .byte 662b-661b\n"     "  .byte 664f-663f\n"     ".previous\n"   ".section .altinstr_replacement,\"ax\"\n"   "663:\n\t" newinstr "\n664:\n"    ".previous" :: "i" (feature) : "memory")
#define alternative_input(oldinstr, newinstr, feature, input...)   asm volatile ("661:\n\t" oldinstr "\n662:\n"   ".section .altinstructions,\"a\"\n"   "  .align 4\n"   "  .long 661b\n"     "  .long 663f\n"     "  .byte %c0\n"     "  .byte 662b-661b\n"     "  .byte 664f-663f\n"     ".previous\n"   ".section .altinstr_replacement,\"ax\"\n"   "663:\n\t" newinstr "\n664:\n"    ".previous" :: "i" (feature), ##input)
#define alternative_io(oldinstr, newinstr, feature, output, input...)   asm volatile ("661:\n\t" oldinstr "\n662:\n"   ".section .altinstructions,\"a\"\n"   "  .align 4\n"   "  .long 661b\n"     "  .long 663f\n"     "  .byte %c[feat]\n"     "  .byte 662b-661b\n"     "  .byte 664f-663f\n"     ".previous\n"   ".section .altinstr_replacement,\"ax\"\n"   "663:\n\t" newinstr "\n664:\n"     ".previous" : output : [feat] "i" (feature), ##input)
#define ASM_OUTPUT2(a, b) a, b
#define LOCK_PREFIX ""

#define __parainstructions NULL
#define __parainstructions_end NULL

#endif
