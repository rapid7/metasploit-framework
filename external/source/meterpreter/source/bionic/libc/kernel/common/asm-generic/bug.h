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
#ifndef _ASM_GENERIC_BUG_H
#define _ASM_GENERIC_BUG_H

#include <linux/compiler.h>

#ifndef HAVE_ARCH_BUG
#define BUG()
#endif

#ifndef HAVE_ARCH_BUG_ON
#define BUG_ON(condition) do { if (condition) ; } while(0)
#endif

#ifndef HAVE_ARCH_WARN_ON
#define WARN_ON(condition) do { if (condition) ; } while(0)
#endif

#define WARN_ON_ONCE(condition)  ({   static int __warn_once = 1;   int __ret = 0;     if (unlikely((condition) && __warn_once)) {   __warn_once = 0;   WARN_ON(1);   __ret = 1;   }   __ret;  })

#define WARN_ON_SMP(x) do { } while (0)

#endif
