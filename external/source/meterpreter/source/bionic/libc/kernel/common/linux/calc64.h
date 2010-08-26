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
#ifndef _LINUX_CALC64_H
#define _LINUX_CALC64_H

#include <linux/types.h>
#include <asm/div64.h>

#ifndef div_long_long_rem
#define div_long_long_rem(dividend, divisor, remainder)   do_div_llr((dividend), divisor, remainder)

#endif
#endif
