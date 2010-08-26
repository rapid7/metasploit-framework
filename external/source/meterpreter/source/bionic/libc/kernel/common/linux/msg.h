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
#ifndef _LINUX_MSG_H
#define _LINUX_MSG_H

#include <linux/ipc.h>

#define MSG_STAT 11
#define MSG_INFO 12

#define MSG_NOERROR 010000  
#define MSG_EXCEPT 020000  

struct msqid_ds {
 struct ipc_perm msg_perm;
 struct msg *msg_first;
 struct msg *msg_last;
 __kernel_time_t msg_stime;
 __kernel_time_t msg_rtime;
 __kernel_time_t msg_ctime;
 unsigned long msg_lcbytes;
 unsigned long msg_lqbytes;
 unsigned short msg_cbytes;
 unsigned short msg_qnum;
 unsigned short msg_qbytes;
 __kernel_ipc_pid_t msg_lspid;
 __kernel_ipc_pid_t msg_lrpid;
};

#include <asm/msgbuf.h>

struct msgbuf {
 long mtype;
 char mtext[1];
};

struct msginfo {
 int msgpool;
 int msgmap;
 int msgmax;
 int msgmnb;
 int msgmni;
 int msgssz;
 int msgtql;
 unsigned short msgseg;
};

#define MSGMNI 16    
#define MSGMAX 8192    
#define MSGMNB 16384    

#define MSGPOOL (MSGMNI*MSGMNB/1024)  
#define MSGTQL MSGMNB  
#define MSGMAP MSGMNB  
#define MSGSSZ 16  
#define __MSGSEG ((MSGPOOL*1024)/ MSGSSZ)  
#define MSGSEG (__MSGSEG <= 0xffff ? __MSGSEG : 0xffff)

#endif
