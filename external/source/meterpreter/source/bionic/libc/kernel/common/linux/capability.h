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
#ifndef _LINUX_CAPABILITY_H
#define _LINUX_CAPABILITY_H

#include <linux/types.h>
#include <linux/compiler.h>

#define _LINUX_CAPABILITY_VERSION 0x19980330

typedef struct __user_cap_header_struct {
 __u32 version;
 int pid;
} __user *cap_user_header_t;

typedef struct __user_cap_data_struct {
 __u32 effective;
 __u32 permitted;
 __u32 inheritable;
} __user *cap_user_data_t;

#define CAP_CHOWN 0

#define CAP_DAC_OVERRIDE 1

#define CAP_DAC_READ_SEARCH 2

#define CAP_FOWNER 3

#define CAP_FSETID 4

#define CAP_FS_MASK 0x1f

#define CAP_KILL 5

#define CAP_SETGID 6

#define CAP_SETUID 7

#define CAP_SETPCAP 8

#define CAP_LINUX_IMMUTABLE 9

#define CAP_NET_BIND_SERVICE 10

#define CAP_NET_BROADCAST 11

#define CAP_NET_ADMIN 12

#define CAP_NET_RAW 13

#define CAP_IPC_LOCK 14

#define CAP_IPC_OWNER 15

#define CAP_SYS_MODULE 16

#define CAP_SYS_RAWIO 17

#define CAP_SYS_CHROOT 18

#define CAP_SYS_PTRACE 19

#define CAP_SYS_PACCT 20

#define CAP_SYS_ADMIN 21

#define CAP_SYS_BOOT 22

#define CAP_SYS_NICE 23

#define CAP_SYS_RESOURCE 24

#define CAP_SYS_TIME 25

#define CAP_SYS_TTY_CONFIG 26

#define CAP_MKNOD 27

#define CAP_LEASE 28

#define CAP_AUDIT_WRITE 29

#define CAP_AUDIT_CONTROL 30

#endif
