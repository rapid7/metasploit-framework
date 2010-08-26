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
#ifndef _ASM_X86_STATFS_H
#define _ASM_X86_STATFS_H

#ifdef __i386__
#include <asm-generic/statfs.h>
#else

struct statfs {
 long f_type;
 long f_bsize;
 long f_blocks;
 long f_bfree;
 long f_bavail;
 long f_files;
 long f_ffree;
 __kernel_fsid_t f_fsid;
 long f_namelen;
 long f_frsize;
 long f_spare[5];
};

struct statfs64 {
 long f_type;
 long f_bsize;
 long f_blocks;
 long f_bfree;
 long f_bavail;
 long f_files;
 long f_ffree;
 __kernel_fsid_t f_fsid;
 long f_namelen;
 long f_frsize;
 long f_spare[5];
};

struct compat_statfs64 {
 __u32 f_type;
 __u32 f_bsize;
 __u64 f_blocks;
 __u64 f_bfree;
 __u64 f_bavail;
 __u64 f_files;
 __u64 f_ffree;
 __kernel_fsid_t f_fsid;
 __u32 f_namelen;
 __u32 f_frsize;
 __u32 f_spare[5];
} __attribute__((packed));

#endif
#endif
