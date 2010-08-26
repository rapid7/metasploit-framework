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
#ifndef _LINUX_SUNRPC_TIMER_H
#define _LINUX_SUNRPC_TIMER_H

#include <asm/atomic.h>

struct rpc_rtt {
 unsigned long timeo;
 unsigned long srtt[5];
 unsigned long sdrtt[5];
 int ntimeouts[5];
};

#endif
