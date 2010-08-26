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
#ifndef _QNX4TYPES_H
#define _QNX4TYPES_H

typedef __le16 qnx4_nxtnt_t;
typedef __u8 qnx4_ftype_t;

typedef struct {
 __le32 xtnt_blk;
 __le32 xtnt_size;
} qnx4_xtnt_t;

typedef __le16 qnx4_mode_t;
typedef __le16 qnx4_muid_t;
typedef __le16 qnx4_mgid_t;
typedef __le32 qnx4_off_t;
typedef __le16 qnx4_nlink_t;

#endif
