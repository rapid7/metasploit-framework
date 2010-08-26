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
#ifndef __LINUX_UIO_H
#define __LINUX_UIO_H

#include <linux/compiler.h>
#include <linux/types.h>

struct iovec
{
 void __user *iov_base;
 __kernel_size_t iov_len;
};

#define UIO_FASTIOV 8
#define UIO_MAXIOV 1024

#endif
