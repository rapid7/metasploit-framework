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
#ifndef _LINUX_POSIX_TYPES_H
#define _LINUX_POSIX_TYPES_H

#include <linux/stddef.h>

#undef __NFDBITS
#define __NFDBITS (8 * sizeof(unsigned long))

#undef __FD_SETSIZE
#define __FD_SETSIZE 1024

#undef __FDSET_LONGS
#define __FDSET_LONGS (__FD_SETSIZE/__NFDBITS)

#undef __FDELT
#define __FDELT(d) ((d) / __NFDBITS)

#undef __FDMASK
#define __FDMASK(d) (1UL << ((d) % __NFDBITS))

typedef struct {
 unsigned long fds_bits [__FDSET_LONGS];
} __kernel_fd_set;

typedef void (*__kernel_sighandler_t)(int);

typedef int __kernel_key_t;
typedef int __kernel_mqd_t;

#include <asm/posix_types.h>

#endif
