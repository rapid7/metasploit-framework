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
#ifndef __ASM_ARM_DELAY_H
#define __ASM_ARM_DELAY_H

#include <asm/param.h>  

#define MAX_UDELAY_MS 2

#define udelay(n)   (__builtin_constant_p(n) ?   ((n) > (MAX_UDELAY_MS * 1000) ? __bad_udelay() :   __const_udelay((n) * ((2199023U*HZ)>>11))) :   __udelay(n))

#endif

