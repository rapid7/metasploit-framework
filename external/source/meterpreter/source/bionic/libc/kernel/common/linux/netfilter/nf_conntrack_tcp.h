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
#ifndef _NF_CONNTRACK_TCP_H
#define _NF_CONNTRACK_TCP_H

enum tcp_conntrack {
 TCP_CONNTRACK_NONE,
 TCP_CONNTRACK_SYN_SENT,
 TCP_CONNTRACK_SYN_RECV,
 TCP_CONNTRACK_ESTABLISHED,
 TCP_CONNTRACK_FIN_WAIT,
 TCP_CONNTRACK_CLOSE_WAIT,
 TCP_CONNTRACK_LAST_ACK,
 TCP_CONNTRACK_TIME_WAIT,
 TCP_CONNTRACK_CLOSE,
 TCP_CONNTRACK_LISTEN,
 TCP_CONNTRACK_MAX,
 TCP_CONNTRACK_IGNORE
};

#define IP_CT_TCP_FLAG_WINDOW_SCALE 0x01

#define IP_CT_TCP_FLAG_SACK_PERM 0x02

#define IP_CT_TCP_FLAG_CLOSE_INIT 0x03

#endif
