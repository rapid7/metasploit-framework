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
#ifndef _ASM_X86_UNALIGNED_H
#define _ASM_X86_UNALIGNED_H

#define get_unaligned(ptr) (*(ptr))

#define put_unaligned(val, ptr) ((void)( *(ptr) = (val) ))

#endif
