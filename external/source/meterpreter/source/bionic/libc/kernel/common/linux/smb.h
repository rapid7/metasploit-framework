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
#ifndef _LINUX_SMB_H
#define _LINUX_SMB_H

#include <linux/types.h>

enum smb_protocol {
 SMB_PROTOCOL_NONE,
 SMB_PROTOCOL_CORE,
 SMB_PROTOCOL_COREPLUS,
 SMB_PROTOCOL_LANMAN1,
 SMB_PROTOCOL_LANMAN2,
 SMB_PROTOCOL_NT1
};

enum smb_case_hndl {
 SMB_CASE_DEFAULT,
 SMB_CASE_LOWER,
 SMB_CASE_UPPER
};

struct smb_dskattr {
 __u16 total;
 __u16 allocblocks;
 __u16 blocksize;
 __u16 free;
};

struct smb_conn_opt {

 unsigned int fd;

 enum smb_protocol protocol;
 enum smb_case_hndl case_handling;

 __u32 max_xmit;
 __u16 server_uid;
 __u16 tid;

 __u16 secmode;
 __u16 maxmux;
 __u16 maxvcs;
 __u16 rawmode;
 __u32 sesskey;

 __u32 maxraw;
 __u32 capabilities;
 __s16 serverzone;
};

#endif
