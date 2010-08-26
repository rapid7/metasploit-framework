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
#ifndef _LINUX_DELAY_H
#define _LINUX_DELAY_H

#include <asm/delay.h>

#ifndef MAX_UDELAY_MS
#define MAX_UDELAY_MS 5
#endif

#ifndef mdelay
#define mdelay(n) (  (__builtin_constant_p(n) && (n)<=MAX_UDELAY_MS) ? udelay((n)*1000) :   ({unsigned long __ms=(n); while (__ms--) udelay(1000);}))
#endif

#ifndef ndelay
#define ndelay(x) udelay(((x)+999)/1000)
#endif

#endif
