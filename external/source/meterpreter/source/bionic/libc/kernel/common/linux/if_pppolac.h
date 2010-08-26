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
#ifndef __LINUX_IF_PPPOLAC_H
#define __LINUX_IF_PPPOLAC_H

#include <linux/socket.h>
#include <linux/types.h>

#define PX_PROTO_OLAC 2

struct sockaddr_pppolac {
 sa_family_t sa_family;
 unsigned int sa_protocol;
 int udp_socket;
 struct __attribute__((packed)) {
 __u16 tunnel, session;
 } local, remote;
} __attribute__((packed));

#endif
