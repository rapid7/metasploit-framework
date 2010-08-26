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
#ifndef NFSD_EXPORT_H
#define NFSD_EXPORT_H

#include <asm/types.h>

#define NFSCLNT_IDMAX 1024
#define NFSCLNT_ADDRMAX 16
#define NFSCLNT_KEYMAX 32

#define NFSEXP_READONLY 0x0001
#define NFSEXP_INSECURE_PORT 0x0002
#define NFSEXP_ROOTSQUASH 0x0004
#define NFSEXP_ALLSQUASH 0x0008
#define NFSEXP_ASYNC 0x0010
#define NFSEXP_GATHERED_WRITES 0x0020

#define NFSEXP_NOHIDE 0x0200
#define NFSEXP_NOSUBTREECHECK 0x0400
#define NFSEXP_NOAUTHNLM 0x0800  
#define NFSEXP_MSNFS 0x1000  
#define NFSEXP_FSID 0x2000
#define NFSEXP_CROSSMOUNT 0x4000
#define NFSEXP_NOACL 0x8000  
#define NFSEXP_ALLFLAGS 0xFE3F

#endif

