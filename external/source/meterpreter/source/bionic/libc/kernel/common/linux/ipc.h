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
#ifndef _LINUX_IPC_H
#define _LINUX_IPC_H

#include <linux/types.h>

#define IPC_PRIVATE ((__kernel_key_t) 0) 

struct ipc_perm
{
 __kernel_key_t key;
 __kernel_uid_t uid;
 __kernel_gid_t gid;
 __kernel_uid_t cuid;
 __kernel_gid_t cgid;
 __kernel_mode_t mode;
 unsigned short seq;
};

#include <asm/ipcbuf.h>

#define IPC_CREAT 00001000  
#define IPC_EXCL 00002000  
#define IPC_NOWAIT 00004000  

#define IPC_DIPC 00010000  
#define IPC_OWN 00020000  

#define IPC_RMID 0  
#define IPC_SET 1  
#define IPC_STAT 2  
#define IPC_INFO 3  

#define IPC_OLD 0  
#define IPC_64 0x0100  

#endif

