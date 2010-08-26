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
#ifndef LINUX_LOCKD_NLM_H
#define LINUX_LOCKD_NLM_H

#define NLM_OFFSET_MAX ((s32) 0x7fffffff)
#define NLM4_OFFSET_MAX ((s64) ((~(u64)0) >> 1))

enum {
 NLM_LCK_GRANTED = 0,
 NLM_LCK_DENIED = 1,
 NLM_LCK_DENIED_NOLOCKS = 2,
 NLM_LCK_BLOCKED = 3,
 NLM_LCK_DENIED_GRACE_PERIOD = 4,
};

#define NLM_PROGRAM 100021

#define NLMPROC_NULL 0
#define NLMPROC_TEST 1
#define NLMPROC_LOCK 2
#define NLMPROC_CANCEL 3
#define NLMPROC_UNLOCK 4
#define NLMPROC_GRANTED 5
#define NLMPROC_TEST_MSG 6
#define NLMPROC_LOCK_MSG 7
#define NLMPROC_CANCEL_MSG 8
#define NLMPROC_UNLOCK_MSG 9
#define NLMPROC_GRANTED_MSG 10
#define NLMPROC_TEST_RES 11
#define NLMPROC_LOCK_RES 12
#define NLMPROC_CANCEL_RES 13
#define NLMPROC_UNLOCK_RES 14
#define NLMPROC_GRANTED_RES 15
#define NLMPROC_NSM_NOTIFY 16  
#define NLMPROC_SHARE 20
#define NLMPROC_UNSHARE 21
#define NLMPROC_NM_LOCK 22
#define NLMPROC_FREE_ALL 23

#endif
