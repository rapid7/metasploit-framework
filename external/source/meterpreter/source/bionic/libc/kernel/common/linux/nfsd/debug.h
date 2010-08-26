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
#ifndef LINUX_NFSD_DEBUG_H
#define LINUX_NFSD_DEBUG_H

#include <linux/sunrpc/debug.h>

#ifdef RPC_DEBUG
#define NFSD_DEBUG 1
#endif

#define NFSDDBG_SOCK 0x0001
#define NFSDDBG_FH 0x0002
#define NFSDDBG_EXPORT 0x0004
#define NFSDDBG_SVC 0x0008
#define NFSDDBG_PROC 0x0010
#define NFSDDBG_FILEOP 0x0020
#define NFSDDBG_AUTH 0x0040
#define NFSDDBG_REPCACHE 0x0080
#define NFSDDBG_XDR 0x0100
#define NFSDDBG_LOCKD 0x0200
#define NFSDDBG_ALL 0x7FFF
#define NFSDDBG_NOCHANGE 0xFFFF

#endif
