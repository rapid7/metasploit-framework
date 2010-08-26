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
#ifndef _XT_CONNMARK_H_target
#define _XT_CONNMARK_H_target

enum {
 XT_CONNMARK_SET = 0,
 XT_CONNMARK_SAVE,
 XT_CONNMARK_RESTORE
};

struct xt_connmark_target_info {
 unsigned long mark;
 unsigned long mask;
 u_int8_t mode;
};

#endif
