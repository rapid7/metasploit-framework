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
#ifndef __EFS_FS_I_H__
#define __EFS_FS_I_H__

typedef int32_t efs_block_t;
typedef uint32_t efs_ino_t;

#define EFS_DIRECTEXTENTS 12

typedef union extent_u {
 unsigned char raw[8];
 struct extent_s {
 unsigned int ex_magic:8;
 unsigned int ex_bn:24;
 unsigned int ex_length:8;
 unsigned int ex_offset:24;
 } cooked;
} efs_extent;

typedef struct edevs {
 __be16 odev;
 __be32 ndev;
} efs_devs;

struct efs_dinode {
 __be16 di_mode;
 __be16 di_nlink;
 __be16 di_uid;
 __be16 di_gid;
 __be32 di_size;
 __be32 di_atime;
 __be32 di_mtime;
 __be32 di_ctime;
 __be32 di_gen;
 __be16 di_numextents;
 u_char di_version;
 u_char di_spare;
 union di_addr {
 efs_extent di_extents[EFS_DIRECTEXTENTS];
 efs_devs di_dev;
 } di_u;
};

struct efs_inode_info {
 int numextents;
 int lastextent;

 efs_extent extents[EFS_DIRECTEXTENTS];
 struct inode vfs_inode;
};

#endif

