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
#ifndef _IPT_ECN_TARGET_H
#define _IPT_ECN_TARGET_H
#include <linux/netfilter_ipv4/ipt_DSCP.h>

#define IPT_ECN_IP_MASK (~IPT_DSCP_MASK)

#define IPT_ECN_OP_SET_IP 0x01  
#define IPT_ECN_OP_SET_ECE 0x10  
#define IPT_ECN_OP_SET_CWR 0x20  

#define IPT_ECN_OP_MASK 0xce

struct ipt_ECN_info {
 u_int8_t operation;
 u_int8_t ip_ect;
 union {
 struct {
 u_int8_t ece:1, cwr:1;
 } tcp;
 } proto;
};

#endif
