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
#ifndef LOCKD_XDR_H
#define LOCKD_XDR_H

#include <linux/fs.h>
#include <linux/nfs.h>
#include <linux/sunrpc/xdr.h>

#define NLM_MAXCOOKIELEN 32
#define NLM_MAXSTRLEN 1024

#define nlm_granted __constant_htonl(NLM_LCK_GRANTED)
#define nlm_lck_denied __constant_htonl(NLM_LCK_DENIED)
#define nlm_lck_denied_nolocks __constant_htonl(NLM_LCK_DENIED_NOLOCKS)
#define nlm_lck_blocked __constant_htonl(NLM_LCK_BLOCKED)
#define nlm_lck_denied_grace_period __constant_htonl(NLM_LCK_DENIED_GRACE_PERIOD)

struct nlm_lock {
 char * caller;
 int len;
 struct nfs_fh fh;
 struct xdr_netobj oh;
 u32 svid;
 struct file_lock fl;
};

struct nlm_cookie
{
 unsigned char data[NLM_MAXCOOKIELEN];
 unsigned int len;
};

struct nlm_args {
 struct nlm_cookie cookie;
 struct nlm_lock lock;
 u32 block;
 u32 reclaim;
 u32 state;
 u32 monitor;
 u32 fsm_access;
 u32 fsm_mode;
};

typedef struct nlm_args nlm_args;

struct nlm_res {
 struct nlm_cookie cookie;
 u32 status;
 struct nlm_lock lock;
};

struct nlm_reboot {
 char * mon;
 int len;
 u32 state;
 u32 addr;
 u32 vers;
 u32 proto;
};

#define NLMSVC_XDRSIZE sizeof(struct nlm_args)

#endif
