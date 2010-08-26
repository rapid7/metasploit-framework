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
#ifndef _NFNETLINK_H
#define _NFNETLINK_H
#include <linux/types.h>

#define NF_NETLINK_CONNTRACK_NEW 0x00000001
#define NF_NETLINK_CONNTRACK_UPDATE 0x00000002
#define NF_NETLINK_CONNTRACK_DESTROY 0x00000004
#define NF_NETLINK_CONNTRACK_EXP_NEW 0x00000008
#define NF_NETLINK_CONNTRACK_EXP_UPDATE 0x00000010
#define NF_NETLINK_CONNTRACK_EXP_DESTROY 0x00000020

enum nfnetlink_groups {
 NFNLGRP_NONE,
#define NFNLGRP_NONE NFNLGRP_NONE
 NFNLGRP_CONNTRACK_NEW,
#define NFNLGRP_CONNTRACK_NEW NFNLGRP_CONNTRACK_NEW
 NFNLGRP_CONNTRACK_UPDATE,
#define NFNLGRP_CONNTRACK_UPDATE NFNLGRP_CONNTRACK_UPDATE
 NFNLGRP_CONNTRACK_DESTROY,
#define NFNLGRP_CONNTRACK_DESTROY NFNLGRP_CONNTRACK_DESTROY
 NFNLGRP_CONNTRACK_EXP_NEW,
#define NFNLGRP_CONNTRACK_EXP_NEW NFNLGRP_CONNTRACK_EXP_NEW
 NFNLGRP_CONNTRACK_EXP_UPDATE,
#define NFNLGRP_CONNTRACK_EXP_UPDATE NFNLGRP_CONNTRACK_EXP_UPDATE
 NFNLGRP_CONNTRACK_EXP_DESTROY,
#define NFNLGRP_CONNTRACK_EXP_DESTROY NFNLGRP_CONNTRACK_EXP_DESTROY
 __NFNLGRP_MAX,
};
#define NFNLGRP_MAX (__NFNLGRP_MAX - 1)

struct nfattr
{
 u_int16_t nfa_len;
 u_int16_t nfa_type;
} __attribute__ ((packed));

#define NFNL_NFA_NEST 0x8000
#define NFA_TYPE(attr) ((attr)->nfa_type & 0x7fff)

#define NFA_ALIGNTO 4
#define NFA_ALIGN(len) (((len) + NFA_ALIGNTO - 1) & ~(NFA_ALIGNTO - 1))
#define NFA_OK(nfa,len) ((len) > 0 && (nfa)->nfa_len >= sizeof(struct nfattr)   && (nfa)->nfa_len <= (len))
#define NFA_NEXT(nfa,attrlen) ((attrlen) -= NFA_ALIGN((nfa)->nfa_len),   (struct nfattr *)(((char *)(nfa)) + NFA_ALIGN((nfa)->nfa_len)))
#define NFA_LENGTH(len) (NFA_ALIGN(sizeof(struct nfattr)) + (len))
#define NFA_SPACE(len) NFA_ALIGN(NFA_LENGTH(len))
#define NFA_DATA(nfa) ((void *)(((char *)(nfa)) + NFA_LENGTH(0)))
#define NFA_PAYLOAD(nfa) ((int)((nfa)->nfa_len) - NFA_LENGTH(0))
#define NFA_NEST(skb, type)  ({ struct nfattr *__start = (struct nfattr *) (skb)->tail;   NFA_PUT(skb, (NFNL_NFA_NEST | type), 0, NULL);   __start; })
#define NFA_NEST_END(skb, start)  ({ (start)->nfa_len = ((skb)->tail - (unsigned char *) (start));   (skb)->len; })
#define NFA_NEST_CANCEL(skb, start)  ({ if (start)   skb_trim(skb, (unsigned char *) (start) - (skb)->data);   -1; })

struct nfgenmsg {
 u_int8_t nfgen_family;
 u_int8_t version;
 u_int16_t res_id;
} __attribute__ ((packed));

#define NFNETLINK_V0 0

#define NFM_NFA(n) ((struct nfattr *)(((char *)(n))   + NLMSG_ALIGN(sizeof(struct nfgenmsg))))
#define NFM_PAYLOAD(n) NLMSG_PAYLOAD(n, sizeof(struct nfgenmsg))

#define NFNL_SUBSYS_ID(x) ((x & 0xff00) >> 8)
#define NFNL_MSG_TYPE(x) (x & 0x00ff)

#define NFNL_SUBSYS_NONE 0
#define NFNL_SUBSYS_CTNETLINK 1
#define NFNL_SUBSYS_CTNETLINK_EXP 2
#define NFNL_SUBSYS_QUEUE 3
#define NFNL_SUBSYS_ULOG 4
#define NFNL_SUBSYS_COUNT 5

#endif
