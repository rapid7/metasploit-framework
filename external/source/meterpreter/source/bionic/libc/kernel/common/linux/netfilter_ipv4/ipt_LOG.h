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
#ifndef _IPT_LOG_H
#define _IPT_LOG_H

#define IPT_LOG_TCPSEQ 0x01  
#define IPT_LOG_TCPOPT 0x02  
#define IPT_LOG_IPOPT 0x04  
#define IPT_LOG_UID 0x08  
#define IPT_LOG_NFLOG 0x10  
#define IPT_LOG_MASK 0x1f

struct ipt_log_info {
 unsigned char level;
 unsigned char logflags;
 char prefix[30];
};

#endif
