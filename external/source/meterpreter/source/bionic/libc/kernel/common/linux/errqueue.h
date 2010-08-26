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
#ifndef _LINUX_ERRQUEUE_H
#define _LINUX_ERRQUEUE_H 1

struct sock_extended_err
{
 __u32 ee_errno;
 __u8 ee_origin;
 __u8 ee_type;
 __u8 ee_code;
 __u8 ee_pad;
 __u32 ee_info;
 __u32 ee_data;
};

#define SO_EE_ORIGIN_NONE 0
#define SO_EE_ORIGIN_LOCAL 1
#define SO_EE_ORIGIN_ICMP 2
#define SO_EE_ORIGIN_ICMP6 3

#define SO_EE_OFFENDER(ee) ((struct sockaddr*)((ee)+1))

#endif
