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
#ifndef __ASM_GENERIC_SIGNAL_H
#define __ASM_GENERIC_SIGNAL_H

#include <linux/compiler.h>

#ifndef SIG_BLOCK
#define SIG_BLOCK 0  
#endif
#ifndef SIG_UNBLOCK
#define SIG_UNBLOCK 1  
#endif
#ifndef SIG_SETMASK
#define SIG_SETMASK 2  
#endif

#ifndef __ASSEMBLY__
typedef void __signalfn_t(int);
typedef __signalfn_t __user *__sighandler_t;

typedef void __restorefn_t(void);
typedef __restorefn_t __user *__sigrestore_t;

#define SIG_DFL ((__force __sighandler_t)0)  
#define SIG_IGN ((__force __sighandler_t)1)  
#define SIG_ERR ((__force __sighandler_t)-1)  
#endif

#endif
