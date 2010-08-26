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
#ifndef __LINUX_NFSACL_H
#define __LINUX_NFSACL_H

#define NFS_ACL_PROGRAM 100227

#define ACLPROC2_GETACL 1
#define ACLPROC2_SETACL 2
#define ACLPROC2_GETATTR 3
#define ACLPROC2_ACCESS 4

#define ACLPROC3_GETACL 1
#define ACLPROC3_SETACL 2

#define NFS_ACL 0x0001
#define NFS_ACLCNT 0x0002
#define NFS_DFACL 0x0004
#define NFS_DFACLCNT 0x0008

#define NFS_ACL_DEFAULT 0x1000

#endif
