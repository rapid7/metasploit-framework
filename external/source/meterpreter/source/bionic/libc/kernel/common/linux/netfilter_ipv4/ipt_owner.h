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
#ifndef _IPT_OWNER_H
#define _IPT_OWNER_H

#define IPT_OWNER_UID 0x01
#define IPT_OWNER_GID 0x02
#define IPT_OWNER_PID 0x04
#define IPT_OWNER_SID 0x08
#define IPT_OWNER_COMM 0x10

struct ipt_owner_info {
 uid_t uid;
 gid_t gid;
 pid_t pid;
 pid_t sid;
 char comm[16];
 u_int8_t match, invert;
};

#endif
