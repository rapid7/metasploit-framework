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
#ifndef _NF_CONNTRACK_COMMON_H
#define _NF_CONNTRACK_COMMON_H

enum ip_conntrack_info
{

 IP_CT_ESTABLISHED,

 IP_CT_RELATED,

 IP_CT_NEW,

 IP_CT_IS_REPLY,

 IP_CT_NUMBER = IP_CT_IS_REPLY * 2 - 1
};

enum ip_conntrack_status {

 IPS_EXPECTED_BIT = 0,
 IPS_EXPECTED = (1 << IPS_EXPECTED_BIT),

 IPS_SEEN_REPLY_BIT = 1,
 IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),

 IPS_ASSURED_BIT = 2,
 IPS_ASSURED = (1 << IPS_ASSURED_BIT),

 IPS_CONFIRMED_BIT = 3,
 IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),

 IPS_SRC_NAT_BIT = 4,
 IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),

 IPS_DST_NAT_BIT = 5,
 IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),

 IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),

 IPS_SEQ_ADJUST_BIT = 6,
 IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),

 IPS_SRC_NAT_DONE_BIT = 7,
 IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT),

 IPS_DST_NAT_DONE_BIT = 8,
 IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT),

 IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE),

 IPS_DYING_BIT = 9,
 IPS_DYING = (1 << IPS_DYING_BIT),

 IPS_FIXED_TIMEOUT_BIT = 10,
 IPS_FIXED_TIMEOUT = (1 << IPS_FIXED_TIMEOUT_BIT),
};

enum ip_conntrack_events
{

 IPCT_NEW_BIT = 0,
 IPCT_NEW = (1 << IPCT_NEW_BIT),

 IPCT_RELATED_BIT = 1,
 IPCT_RELATED = (1 << IPCT_RELATED_BIT),

 IPCT_DESTROY_BIT = 2,
 IPCT_DESTROY = (1 << IPCT_DESTROY_BIT),

 IPCT_REFRESH_BIT = 3,
 IPCT_REFRESH = (1 << IPCT_REFRESH_BIT),

 IPCT_STATUS_BIT = 4,
 IPCT_STATUS = (1 << IPCT_STATUS_BIT),

 IPCT_PROTOINFO_BIT = 5,
 IPCT_PROTOINFO = (1 << IPCT_PROTOINFO_BIT),

 IPCT_PROTOINFO_VOLATILE_BIT = 6,
 IPCT_PROTOINFO_VOLATILE = (1 << IPCT_PROTOINFO_VOLATILE_BIT),

 IPCT_HELPER_BIT = 7,
 IPCT_HELPER = (1 << IPCT_HELPER_BIT),

 IPCT_HELPINFO_BIT = 8,
 IPCT_HELPINFO = (1 << IPCT_HELPINFO_BIT),

 IPCT_HELPINFO_VOLATILE_BIT = 9,
 IPCT_HELPINFO_VOLATILE = (1 << IPCT_HELPINFO_VOLATILE_BIT),

 IPCT_NATINFO_BIT = 10,
 IPCT_NATINFO = (1 << IPCT_NATINFO_BIT),

 IPCT_COUNTER_FILLING_BIT = 11,
 IPCT_COUNTER_FILLING = (1 << IPCT_COUNTER_FILLING_BIT),
};

enum ip_conntrack_expect_events {
 IPEXP_NEW_BIT = 0,
 IPEXP_NEW = (1 << IPEXP_NEW_BIT),
};

#endif
