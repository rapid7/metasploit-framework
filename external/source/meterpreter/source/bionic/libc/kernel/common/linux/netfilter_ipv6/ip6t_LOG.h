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
#ifndef _IP6T_LOG_H
#define _IP6T_LOG_H

#define IP6T_LOG_TCPSEQ 0x01  
#define IP6T_LOG_TCPOPT 0x02  
#define IP6T_LOG_IPOPT 0x04  
#define IP6T_LOG_UID 0x08  
#define IP6T_LOG_NFLOG 0x10  
#define IP6T_LOG_MASK 0x1f

struct ip6t_log_info {
 unsigned char level;
 unsigned char logflags;
 char prefix[30];
};

#endif
