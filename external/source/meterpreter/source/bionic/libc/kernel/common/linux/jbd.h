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
#ifndef _LINUX_JBD_H
#define _LINUX_JBD_H

#include "jfs_compat.h"
#define JFS_DEBUG
#define jfs_debug jbd_debug

#define journal_oom_retry 1

#undef JBD_PARANOID_IOFAIL

#define JBD_DEFAULT_MAX_COMMIT_AGE 5

#define jbd_debug(f, a...)  

#define jbd_kmalloc(size, flags)   __jbd_kmalloc(__FUNCTION__, (size), (flags), journal_oom_retry)
#define jbd_rep_kmalloc(size, flags)   __jbd_kmalloc(__FUNCTION__, (size), (flags), 1)

#define JFS_MIN_JOURNAL_BLOCKS 1024

#define JFS_MAGIC_NUMBER 0xc03b3998U  

#define JFS_DESCRIPTOR_BLOCK 1
#define JFS_COMMIT_BLOCK 2
#define JFS_SUPERBLOCK_V1 3
#define JFS_SUPERBLOCK_V2 4
#define JFS_REVOKE_BLOCK 5

typedef struct journal_header_s
{
 __be32 h_magic;
 __be32 h_blocktype;
 __be32 h_sequence;
} journal_header_t;

typedef struct journal_block_tag_s
{
 __be32 t_blocknr;
 __be32 t_flags;
} journal_block_tag_t;

typedef struct journal_revoke_header_s
{
 journal_header_t r_header;
 __be32 r_count;
} journal_revoke_header_t;

#define JFS_FLAG_ESCAPE 1  
#define JFS_FLAG_SAME_UUID 2  
#define JFS_FLAG_DELETED 4  
#define JFS_FLAG_LAST_TAG 8  

typedef struct journal_superblock_s
{

 journal_header_t s_header;

 __be32 s_blocksize;
 __be32 s_maxlen;
 __be32 s_first;

 __be32 s_sequence;
 __be32 s_start;

 __be32 s_errno;

 __be32 s_feature_compat;
 __be32 s_feature_incompat;
 __be32 s_feature_ro_compat;

 __u8 s_uuid[16];

 __be32 s_nr_users;

 __be32 s_dynsuper;

 __be32 s_max_transaction;
 __be32 s_max_trans_data;

 __u32 s_padding[44];

 __u8 s_users[16*48];

} journal_superblock_t;

#define JFS_HAS_COMPAT_FEATURE(j,mask)   ((j)->j_format_version >= 2 &&   ((j)->j_superblock->s_feature_compat & cpu_to_be32((mask))))
#define JFS_HAS_RO_COMPAT_FEATURE(j,mask)   ((j)->j_format_version >= 2 &&   ((j)->j_superblock->s_feature_ro_compat & cpu_to_be32((mask))))
#define JFS_HAS_INCOMPAT_FEATURE(j,mask)   ((j)->j_format_version >= 2 &&   ((j)->j_superblock->s_feature_incompat & cpu_to_be32((mask))))

#define JFS_FEATURE_INCOMPAT_REVOKE 0x00000001

#define JFS_KNOWN_COMPAT_FEATURES 0
#define JFS_KNOWN_ROCOMPAT_FEATURES 0
#define JFS_KNOWN_INCOMPAT_FEATURES JFS_FEATURE_INCOMPAT_REVOKE

#define BJ_None 0  
#define BJ_SyncData 1  
#define BJ_Metadata 2  
#define BJ_Forget 3  
#define BJ_IO 4  
#define BJ_Shadow 5  
#define BJ_LogCtl 6  
#define BJ_Reserved 7  
#define BJ_Locked 8  
#define BJ_Types 9

#endif
