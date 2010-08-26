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
#ifndef __EFS_DIR_H__
#define __EFS_DIR_H__

#define EFS_DIRBSIZE_BITS EFS_BLOCKSIZE_BITS
#define EFS_DIRBSIZE (1 << EFS_DIRBSIZE_BITS)

struct efs_dentry {
 __be32 inode;
 unsigned char namelen;
 char name[3];
};

#define EFS_DENTSIZE (sizeof(struct efs_dentry) - 3 + 1)
#define EFS_MAXNAMELEN ((1 << (sizeof(char) * 8)) - 1)

#define EFS_DIRBLK_HEADERSIZE 4
#define EFS_DIRBLK_MAGIC 0xbeef  

struct efs_dir {
 __be16 magic;
 unsigned char firstused;
 unsigned char slots;

 unsigned char space[EFS_DIRBSIZE - EFS_DIRBLK_HEADERSIZE];
};

#define EFS_MAXENTS   ((EFS_DIRBSIZE - EFS_DIRBLK_HEADERSIZE) /   (EFS_DENTSIZE + sizeof(char)))

#define EFS_SLOTAT(dir, slot) EFS_REALOFF((dir)->space[slot])

#define EFS_REALOFF(offset) ((offset << 1))

#endif

