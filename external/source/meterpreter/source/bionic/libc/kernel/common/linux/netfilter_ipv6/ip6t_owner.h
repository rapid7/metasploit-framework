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
#ifndef _IP6T_OWNER_H
#define _IP6T_OWNER_H

#define IP6T_OWNER_UID 0x01
#define IP6T_OWNER_GID 0x02
#define IP6T_OWNER_PID 0x04
#define IP6T_OWNER_SID 0x08

struct ip6t_owner_info {
 uid_t uid;
 gid_t gid;
 pid_t pid;
 pid_t sid;
 u_int8_t match, invert;
};

#endif
