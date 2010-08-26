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
#ifndef _ASM_GENERIC_IPC_H
#define _ASM_GENERIC_IPC_H

struct ipc_kludge {
 struct msgbuf __user *msgp;
 long msgtyp;
};

#define SEMOP 1
#define SEMGET 2
#define SEMCTL 3
#define SEMTIMEDOP 4
#define MSGSND 11
#define MSGRCV 12
#define MSGGET 13
#define MSGCTL 14
#define SHMAT 21
#define SHMDT 22
#define SHMGET 23
#define SHMCTL 24

#define DIPC 25

#define IPCCALL(version,op) ((version)<<16 | (op))

#endif
