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
#ifndef __LINUX_KMOD_H__
#define __LINUX_KMOD_H__

#include <linux/stddef.h>
#include <linux/errno.h>
#include <linux/compiler.h>

#define KMOD_PATH_LEN 256

#define try_then_request_module(x, mod...) ((x) ?: (request_module(mod), (x)))

#endif
