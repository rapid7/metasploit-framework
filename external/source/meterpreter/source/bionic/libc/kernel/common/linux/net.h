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
#ifndef _LINUX_NET_H
#define _LINUX_NET_H

#include <linux/wait.h>
#include <asm/socket.h>

struct poll_table_struct;
struct inode;

#define NPROTO 32  

#define SYS_SOCKET 1  
#define SYS_BIND 2  
#define SYS_CONNECT 3  
#define SYS_LISTEN 4  
#define SYS_ACCEPT 5  
#define SYS_GETSOCKNAME 6  
#define SYS_GETPEERNAME 7  
#define SYS_SOCKETPAIR 8  
#define SYS_SEND 9  
#define SYS_RECV 10  
#define SYS_SENDTO 11  
#define SYS_RECVFROM 12  
#define SYS_SHUTDOWN 13  
#define SYS_SETSOCKOPT 14  
#define SYS_GETSOCKOPT 15  
#define SYS_SENDMSG 16  
#define SYS_RECVMSG 17  

typedef enum {
 SS_FREE = 0,
 SS_UNCONNECTED,
 SS_CONNECTING,
 SS_CONNECTED,
 SS_DISCONNECTING
} socket_state;

#define __SO_ACCEPTCON (1 << 16)  

#endif
