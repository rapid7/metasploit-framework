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
#ifndef _LINUX_FS_H
#define _LINUX_FS_H

#include <linux/limits.h>
#include <linux/ioctl.h>

#undef NR_OPEN
#define NR_OPEN (1024*1024)  
#define INR_OPEN 1024  

#define BLOCK_SIZE_BITS 10
#define BLOCK_SIZE (1<<BLOCK_SIZE_BITS)

#define SEEK_SET 0  
#define SEEK_CUR 1  
#define SEEK_END 2  

struct files_stat_struct {
 int nr_files;
 int nr_free_files;
 int max_files;
};

struct inodes_stat_t {
 int nr_inodes;
 int nr_unused;
 int dummy[5];
};

#define NR_FILE 8192  

#define MAY_EXEC 1
#define MAY_WRITE 2
#define MAY_READ 4
#define MAY_APPEND 8

#define FMODE_READ 1
#define FMODE_WRITE 2

#define FMODE_LSEEK 4
#define FMODE_PREAD 8
#define FMODE_PWRITE FMODE_PREAD  

#define FMODE_EXEC 16

#define RW_MASK 1
#define RWA_MASK 2
#define READ 0
#define WRITE 1
#define READA 2  
#define SWRITE 3  
#define SPECIAL 4  
#define READ_SYNC (READ | (1 << BIO_RW_SYNC))
#define WRITE_SYNC (WRITE | (1 << BIO_RW_SYNC))
#define WRITE_BARRIER ((1 << BIO_RW) | (1 << BIO_RW_BARRIER))

#define SEL_IN 1
#define SEL_OUT 2
#define SEL_EX 4

#define FS_REQUIRES_DEV 1 
#define FS_BINARY_MOUNTDATA 2
#define FS_REVAL_DOT 16384  
#define FS_ODD_RENAME 32768  

#define MS_RDONLY 1  
#define MS_NOSUID 2  
#define MS_NODEV 4  
#define MS_NOEXEC 8  
#define MS_SYNCHRONOUS 16  
#define MS_REMOUNT 32  
#define MS_MANDLOCK 64  
#define MS_DIRSYNC 128  
#define MS_NOATIME 1024  
#define MS_NODIRATIME 2048  
#define MS_BIND 4096
#define MS_MOVE 8192
#define MS_REC 16384
#define MS_VERBOSE 32768  
#define MS_SILENT 32768
#define MS_POSIXACL (1<<16)  
#define MS_UNBINDABLE (1<<17)  
#define MS_PRIVATE (1<<18)  
#define MS_SLAVE (1<<19)  
#define MS_SHARED (1<<20)  
#define MS_ACTIVE (1<<30)
#define MS_NOUSER (1<<31)

#define MS_RMT_MASK (MS_RDONLY|MS_SYNCHRONOUS|MS_MANDLOCK)

#define MS_MGC_VAL 0xC0ED0000
#define MS_MGC_MSK 0xffff0000

#define S_SYNC 1  
#define S_NOATIME 2  
#define S_APPEND 4  
#define S_IMMUTABLE 8  
#define S_DEAD 16  
#define S_NOQUOTA 32  
#define S_DIRSYNC 64  
#define S_NOCMTIME 128  
#define S_SWAPFILE 256  
#define S_PRIVATE 512  

#define __IS_FLG(inode,flg) ((inode)->i_sb->s_flags & (flg))

#define IS_RDONLY(inode) ((inode)->i_sb->s_flags & MS_RDONLY)
#define IS_SYNC(inode) (__IS_FLG(inode, MS_SYNCHRONOUS) ||   ((inode)->i_flags & S_SYNC))
#define IS_DIRSYNC(inode) (__IS_FLG(inode, MS_SYNCHRONOUS|MS_DIRSYNC) ||   ((inode)->i_flags & (S_SYNC|S_DIRSYNC)))
#define IS_MANDLOCK(inode) __IS_FLG(inode, MS_MANDLOCK)

#define IS_NOQUOTA(inode) ((inode)->i_flags & S_NOQUOTA)
#define IS_APPEND(inode) ((inode)->i_flags & S_APPEND)
#define IS_IMMUTABLE(inode) ((inode)->i_flags & S_IMMUTABLE)
#define IS_POSIXACL(inode) __IS_FLG(inode, MS_POSIXACL)

#define IS_DEADDIR(inode) ((inode)->i_flags & S_DEAD)
#define IS_NOCMTIME(inode) ((inode)->i_flags & S_NOCMTIME)
#define IS_SWAPFILE(inode) ((inode)->i_flags & S_SWAPFILE)
#define IS_PRIVATE(inode) ((inode)->i_flags & S_PRIVATE)

#define BLKROSET _IO(0x12,93)  
#define BLKROGET _IO(0x12,94)  
#define BLKRRPART _IO(0x12,95)  
#define BLKGETSIZE _IO(0x12,96)  
#define BLKFLSBUF _IO(0x12,97)  
#define BLKRASET _IO(0x12,98)  
#define BLKRAGET _IO(0x12,99)  
#define BLKFRASET _IO(0x12,100) 
#define BLKFRAGET _IO(0x12,101) 
#define BLKSECTSET _IO(0x12,102) 
#define BLKSECTGET _IO(0x12,103) 
#define BLKSSZGET _IO(0x12,104) 

#define BLKBSZGET _IOR(0x12,112,size_t)
#define BLKBSZSET _IOW(0x12,113,size_t)
#define BLKGETSIZE64 _IOR(0x12,114,size_t)  
#define BLKTRACESETUP _IOWR(0x12,115,struct blk_user_trace_setup)
#define BLKTRACESTART _IO(0x12,116)
#define BLKTRACESTOP _IO(0x12,117)
#define BLKTRACETEARDOWN _IO(0x12,118)

#define BMAP_IOCTL 1  
#define FIBMAP _IO(0x00,1)  
#define FIGETBSZ _IO(0x00,2)  

#define SYNC_FILE_RANGE_WAIT_BEFORE 1
#define SYNC_FILE_RANGE_WRITE 2
#define SYNC_FILE_RANGE_WAIT_AFTER 4

#endif
