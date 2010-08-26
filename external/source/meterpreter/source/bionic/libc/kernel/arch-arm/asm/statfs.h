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
#ifndef _ASMARM_STATFS_H
#define _ASMARM_STATFS_H

struct statfs {
 __u32 f_type;
 __u32 f_bsize;
 __u32 f_blocks;
 __u32 f_bfree;
 __u32 f_bavail;
 __u32 f_files;
 __u32 f_ffree;
 __kernel_fsid_t f_fsid;
 __u32 f_namelen;
 __u32 f_frsize;
 __u32 f_spare[5];
};

struct statfs64 {
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
} __attribute__ ((packed,aligned(4)));

#endif
