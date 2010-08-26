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
#ifndef __LINUX_UFS_FS_SB_H
#define __LINUX_UFS_FS_SB_H

#define UFS_MAX_GROUP_LOADED 8
#define UFS_CGNO_EMPTY ((unsigned)-1)

struct ufs_sb_private_info;
struct ufs_cg_private_info;
struct ufs_csum;
#define UFS_MAXCSBUFS 31

struct ufs_sb_info {
 struct ufs_sb_private_info * s_uspi;
 struct ufs_csum * s_csp;
 unsigned s_bytesex;
 unsigned s_flags;
 struct buffer_head ** s_ucg;
 struct ufs_cg_private_info * s_ucpi[UFS_MAX_GROUP_LOADED];
 unsigned s_cgno[UFS_MAX_GROUP_LOADED];
 unsigned short s_cg_loaded;
 unsigned s_mount_opt;
};

#endif
