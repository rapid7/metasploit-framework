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
#ifndef _LINUX_SUNRPC_TYPES_H_
#define _LINUX_SUNRPC_TYPES_H_

#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/sunrpc/debug.h>
#include <linux/list.h>

#define signalled() (signal_pending(current))

#endif
