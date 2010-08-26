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
#ifndef _LINUX_SOCKET_H
#define _LINUX_SOCKET_H

#define _K_SS_MAXSIZE 128  
#define _K_SS_ALIGNSIZE (__alignof__ (struct sockaddr *))

struct __kernel_sockaddr_storage {
 unsigned short ss_family;

 char __data[_K_SS_MAXSIZE - sizeof(unsigned short)];

} __attribute__ ((aligned(_K_SS_ALIGNSIZE)));

#if !defined(__GLIBC__) || __GLIBC__ < 2

#include <asm/socket.h>  
#include <linux/sockios.h>  
#include <linux/uio.h>  
#include <linux/types.h>  
#include <linux/compiler.h>  

typedef unsigned short sa_family_t;

struct sockaddr {
 sa_family_t sa_family;
 char sa_data[14];
};

struct linger {
 int l_onoff;
 int l_linger;
};

#define sockaddr_storage __kernel_sockaddr_storage

struct msghdr {
 void * msg_name;
 int msg_namelen;
 struct iovec * msg_iov;
 __kernel_size_t msg_iovlen;
 void * msg_control;
 __kernel_size_t msg_controllen;
 unsigned msg_flags;
};

struct cmsghdr {
 __kernel_size_t cmsg_len;
 int cmsg_level;
 int cmsg_type;
};

#define __CMSG_NXTHDR(ctl, len, cmsg) __cmsg_nxthdr((ctl),(len),(cmsg))
#define CMSG_NXTHDR(mhdr, cmsg) cmsg_nxthdr((mhdr), (cmsg))

#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )

#define CMSG_DATA(cmsg) ((void *)((char *)(cmsg) + CMSG_ALIGN(sizeof(struct cmsghdr))))
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#define CMSG_LEN(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))

#define __CMSG_FIRSTHDR(ctl,len) ((len) >= sizeof(struct cmsghdr) ?   (struct cmsghdr *)(ctl) :   (struct cmsghdr *)NULL)
#define CMSG_FIRSTHDR(msg) __CMSG_FIRSTHDR((msg)->msg_control, (msg)->msg_controllen)
#define CMSG_OK(mhdr, cmsg) ((cmsg)->cmsg_len >= sizeof(struct cmsghdr) &&   (cmsg)->cmsg_len <= (unsigned long)   ((mhdr)->msg_controllen -   ((char *)(cmsg) - (char *)(mhdr)->msg_control)))

#ifdef __GNUC__
#define __KINLINE static __inline__
#elif defined(__cplusplus)
#define __KINLINE static inline
#else
#define __KINLINE static
#endif

__KINLINE struct cmsghdr * __cmsg_nxthdr(void *__ctl, __kernel_size_t __size,
 struct cmsghdr *__cmsg)
{
 struct cmsghdr * __ptr;

 __ptr = (struct cmsghdr*)(((unsigned char *) __cmsg) + CMSG_ALIGN(__cmsg->cmsg_len));
 if ((unsigned long)((char*)(__ptr+1) - (char *) __ctl) > __size)
 return (struct cmsghdr *)0;

 return __ptr;
}

__KINLINE struct cmsghdr * cmsg_nxthdr (struct msghdr *__msg, struct cmsghdr *__cmsg)
{
 return __cmsg_nxthdr(__msg->msg_control, __msg->msg_controllen, __cmsg);
}

#define SCM_RIGHTS 0x01  
#define SCM_CREDENTIALS 0x02  
#define SCM_SECURITY 0x03  

struct ucred {
 __u32 pid;
 __u32 uid;
 __u32 gid;
};

#define AF_UNSPEC 0
#define AF_UNIX 1  
#define AF_LOCAL 1  
#define AF_INET 2  
#define AF_AX25 3  
#define AF_IPX 4  
#define AF_APPLETALK 5  
#define AF_NETROM 6  
#define AF_BRIDGE 7  
#define AF_ATMPVC 8  
#define AF_X25 9  
#define AF_INET6 10  
#define AF_ROSE 11  
#define AF_DECnet 12  
#define AF_NETBEUI 13  
#define AF_SECURITY 14  
#define AF_KEY 15  
#define AF_NETLINK 16
#define AF_ROUTE AF_NETLINK  
#define AF_PACKET 17  
#define AF_ASH 18  
#define AF_ECONET 19  
#define AF_ATMSVC 20  
#define AF_SNA 22  
#define AF_IRDA 23  
#define AF_PPPOX 24  
#define AF_WANPIPE 25  
#define AF_LLC 26  
#define AF_TIPC 30  
#define AF_BLUETOOTH 31  
#define AF_MAX 32  

#define PF_UNSPEC AF_UNSPEC
#define PF_UNIX AF_UNIX
#define PF_LOCAL AF_LOCAL
#define PF_INET AF_INET
#define PF_AX25 AF_AX25
#define PF_IPX AF_IPX
#define PF_APPLETALK AF_APPLETALK
#define PF_NETROM AF_NETROM
#define PF_BRIDGE AF_BRIDGE
#define PF_ATMPVC AF_ATMPVC
#define PF_X25 AF_X25
#define PF_INET6 AF_INET6
#define PF_ROSE AF_ROSE
#define PF_DECnet AF_DECnet
#define PF_NETBEUI AF_NETBEUI
#define PF_SECURITY AF_SECURITY
#define PF_KEY AF_KEY
#define PF_NETLINK AF_NETLINK
#define PF_ROUTE AF_ROUTE
#define PF_PACKET AF_PACKET
#define PF_ASH AF_ASH
#define PF_ECONET AF_ECONET
#define PF_ATMSVC AF_ATMSVC
#define PF_SNA AF_SNA
#define PF_IRDA AF_IRDA
#define PF_PPPOX AF_PPPOX
#define PF_WANPIPE AF_WANPIPE
#define PF_LLC AF_LLC
#define PF_TIPC AF_TIPC
#define PF_BLUETOOTH AF_BLUETOOTH
#define PF_MAX AF_MAX

#define SOMAXCONN 128

#define MSG_OOB 1
#define MSG_PEEK 2
#define MSG_DONTROUTE 4
#define MSG_TRYHARD 4  
#define MSG_CTRUNC 8
#define MSG_PROBE 0x10  
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40  
#define MSG_EOR 0x80  
#define MSG_WAITALL 0x100  
#define MSG_FIN 0x200
#define MSG_SYN 0x400
#define MSG_CONFIRM 0x800  
#define MSG_RST 0x1000
#define MSG_ERRQUEUE 0x2000  
#define MSG_NOSIGNAL 0x4000  
#define MSG_MORE 0x8000  

#define MSG_EOF MSG_FIN

#define MSG_CMSG_COMPAT 0  

#define SOL_IP 0

#define SOL_TCP 6
#define SOL_UDP 17
#define SOL_IPV6 41
#define SOL_ICMPV6 58
#define SOL_SCTP 132
#define SOL_RAW 255
#define SOL_IPX 256
#define SOL_AX25 257
#define SOL_ATALK 258
#define SOL_NETROM 259
#define SOL_ROSE 260
#define SOL_DECNET 261
#define SOL_X25 262
#define SOL_PACKET 263
#define SOL_ATM 264  
#define SOL_AAL 265  
#define SOL_IRDA 266
#define SOL_NETBEUI 267
#define SOL_LLC 268
#define SOL_DCCP 269
#define SOL_NETLINK 270
#define SOL_TIPC 271

#define IPX_TYPE 1

#endif
#endif
