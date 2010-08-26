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
#ifndef _XT_MARK_H_target
#define _XT_MARK_H_target

struct xt_mark_target_info {
 unsigned long mark;
};

enum {
 XT_MARK_SET=0,
 XT_MARK_AND,
 XT_MARK_OR,
};

struct xt_mark_target_info_v1 {
 unsigned long mark;
 u_int8_t mode;
};

#endif
