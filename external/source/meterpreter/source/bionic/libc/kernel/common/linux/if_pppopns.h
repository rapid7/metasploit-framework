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
#ifndef __LINUX_IF_PPPOPNS_H
#define __LINUX_IF_PPPOPNS_H

#include <linux/socket.h>
#include <linux/types.h>

#define PX_PROTO_OPNS 3

struct sockaddr_pppopns {
 sa_family_t sa_family;
 unsigned int sa_protocol;
 int tcp_socket;
 __u16 local;
 __u16 remote;
} __attribute__((packed));

#endif
