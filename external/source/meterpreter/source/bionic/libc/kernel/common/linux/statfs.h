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
#ifndef _LINUX_STATFS_H
#define _LINUX_STATFS_H

#include <linux/types.h>

#include <asm/statfs.h>

struct kstatfs {
 long f_type;
 long f_bsize;
 u64 f_blocks;
 u64 f_bfree;
 u64 f_bavail;
 u64 f_files;
 u64 f_ffree;
 __kernel_fsid_t f_fsid;
 long f_namelen;
 long f_frsize;
 long f_spare[5];
};

#endif
