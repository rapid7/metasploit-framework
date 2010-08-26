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
#include <asm/processor.h>

#define XOR_TRY_TEMPLATES   do {   xor_speed(&xor_block_8regs);   xor_speed(&xor_block_8regs_p);   xor_speed(&xor_block_32regs);   xor_speed(&xor_block_32regs_p);   } while (0)
