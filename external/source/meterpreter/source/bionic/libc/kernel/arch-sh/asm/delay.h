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
#ifndef __ASM_SH_DELAY_H
#define __ASM_SH_DELAY_H

#define udelay(n) (__builtin_constant_p(n) ?   ((n) > 20000 ? __bad_udelay() : __const_udelay((n) * 0x10c6ul)) :   __udelay(n))

#define ndelay(n) (__builtin_constant_p(n) ?   ((n) > 20000 ? __bad_ndelay() : __const_udelay((n) * 5ul)) :   __ndelay(n))

#endif
