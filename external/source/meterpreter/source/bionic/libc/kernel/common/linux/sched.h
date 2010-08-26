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
#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <linux/auxvec.h>  

#define CSIGNAL 0x000000ff  
#define CLONE_VM 0x00000100  
#define CLONE_FS 0x00000200  
#define CLONE_FILES 0x00000400  
#define CLONE_SIGHAND 0x00000800  
#define CLONE_PTRACE 0x00002000  
#define CLONE_VFORK 0x00004000  
#define CLONE_PARENT 0x00008000  
#define CLONE_THREAD 0x00010000  
#define CLONE_NEWNS 0x00020000  
#define CLONE_SYSVSEM 0x00040000  
#define CLONE_SETTLS 0x00080000  
#define CLONE_PARENT_SETTID 0x00100000  
#define CLONE_CHILD_CLEARTID 0x00200000  
#define CLONE_DETACHED 0x00400000  
#define CLONE_UNTRACED 0x00800000  
#define CLONE_CHILD_SETTID 0x01000000  
#define CLONE_STOPPED 0x02000000  

#define SCHED_NORMAL 0
#define SCHED_FIFO 1
#define SCHED_RR 2
#define SCHED_BATCH 3

#endif
