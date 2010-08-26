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
#ifndef _XT_QUOTA_H
#define _XT_QUOTA_H

enum xt_quota_flags {
 XT_QUOTA_INVERT = 0x1,
};
#define XT_QUOTA_MASK 0x1

struct xt_quota_info {
 u_int32_t flags;
 u_int32_t pad;
 aligned_u64 quota;
 struct xt_quota_info *master;
};

#endif
