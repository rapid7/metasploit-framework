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
#ifndef _LINUX_AUTO_FS_H
#define _LINUX_AUTO_FS_H

#include <linux/ioctl.h>

#define AUTOFS_PROTO_VERSION 3

#define AUTOFS_MAX_PROTO_VERSION AUTOFS_PROTO_VERSION
#define AUTOFS_MIN_PROTO_VERSION AUTOFS_PROTO_VERSION

#if defined(__sparc__) || defined(__mips__) || defined(__x86_64__) || defined(__powerpc__) || defined(__s390__)
typedef unsigned int autofs_wqt_t;
#else
typedef unsigned long autofs_wqt_t;
#endif

#define autofs_ptype_missing 0  
#define autofs_ptype_expire 1  

struct autofs_packet_hdr {
 int proto_version;
 int type;
};

struct autofs_packet_missing {
 struct autofs_packet_hdr hdr;
 autofs_wqt_t wait_queue_token;
 int len;
 char name[NAME_MAX+1];
};

struct autofs_packet_expire {
 struct autofs_packet_hdr hdr;
 int len;
 char name[NAME_MAX+1];
};

#define AUTOFS_IOC_READY _IO(0x93,0x60)
#define AUTOFS_IOC_FAIL _IO(0x93,0x61)
#define AUTOFS_IOC_CATATONIC _IO(0x93,0x62)
#define AUTOFS_IOC_PROTOVER _IOR(0x93,0x63,int)
#define AUTOFS_IOC_SETTIMEOUT _IOWR(0x93,0x64,unsigned long)
#define AUTOFS_IOC_EXPIRE _IOR(0x93,0x65,struct autofs_packet_expire)

#endif
