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
#ifndef _LINUX_UFS_FS_I_H
#define _LINUX_UFS_FS_I_H

struct ufs_inode_info {
 union {
 __fs32 i_data[15];
 __u8 i_symlink[4*15];
 __fs64 u2_i_data[15];
 } i_u1;
 __u32 i_flags;
 __u32 i_gen;
 __u32 i_shadow;
 __u32 i_unused1;
 __u32 i_unused2;
 __u32 i_oeftflag;
 __u16 i_osync;
 __u32 i_lastfrag;
 __u32 i_dir_start_lookup;
 struct inode vfs_inode;
};

#endif
