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
#ifndef _LINUX_QUOTA_
#define _LINUX_QUOTA_

#include <linux/errno.h>
#include <linux/types.h>

#define __DQUOT_VERSION__ "dquot_6.5.1"
#define __DQUOT_NUM_VERSION__ 6*10000+5*100+1

typedef __kernel_uid32_t qid_t;
typedef __u64 qsize_t;

#define QUOTABLOCK_BITS 10
#define QUOTABLOCK_SIZE (1 << QUOTABLOCK_BITS)

#define qb2kb(x) ((x) << (QUOTABLOCK_BITS-10))
#define kb2qb(x) ((x) >> (QUOTABLOCK_BITS-10))
#define toqb(x) (((x) + QUOTABLOCK_SIZE - 1) >> QUOTABLOCK_BITS)

#define MAXQUOTAS 2
#define USRQUOTA 0  
#define GRPQUOTA 1  

#define INITQFNAMES {   "user",     "group",     "undefined",  };

#define SUBCMDMASK 0x00ff
#define SUBCMDSHIFT 8
#define QCMD(cmd, type) (((cmd) << SUBCMDSHIFT) | ((type) & SUBCMDMASK))

#define Q_SYNC 0x800001  
#define Q_QUOTAON 0x800002  
#define Q_QUOTAOFF 0x800003  
#define Q_GETFMT 0x800004  
#define Q_GETINFO 0x800005  
#define Q_SETINFO 0x800006  
#define Q_GETQUOTA 0x800007  
#define Q_SETQUOTA 0x800008  

#define QIF_BLIMITS 1
#define QIF_SPACE 2
#define QIF_ILIMITS 4
#define QIF_INODES 8
#define QIF_BTIME 16
#define QIF_ITIME 32
#define QIF_LIMITS (QIF_BLIMITS | QIF_ILIMITS)
#define QIF_USAGE (QIF_SPACE | QIF_INODES)
#define QIF_TIMES (QIF_BTIME | QIF_ITIME)
#define QIF_ALL (QIF_LIMITS | QIF_USAGE | QIF_TIMES)

struct if_dqblk {
 __u64 dqb_bhardlimit;
 __u64 dqb_bsoftlimit;
 __u64 dqb_curspace;
 __u64 dqb_ihardlimit;
 __u64 dqb_isoftlimit;
 __u64 dqb_curinodes;
 __u64 dqb_btime;
 __u64 dqb_itime;
 __u32 dqb_valid;
};

#define IIF_BGRACE 1
#define IIF_IGRACE 2
#define IIF_FLAGS 4
#define IIF_ALL (IIF_BGRACE | IIF_IGRACE | IIF_FLAGS)

struct if_dqinfo {
 __u64 dqi_bgrace;
 __u64 dqi_igrace;
 __u32 dqi_flags;
 __u32 dqi_valid;
};

#include <sys/cdefs.h>

#endif
