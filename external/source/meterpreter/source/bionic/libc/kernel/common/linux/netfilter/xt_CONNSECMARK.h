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
#ifndef _XT_CONNSECMARK_H_target
#define _XT_CONNSECMARK_H_target

enum {
 CONNSECMARK_SAVE = 1,
 CONNSECMARK_RESTORE,
};

struct xt_connsecmark_target_info {
 u_int8_t mode;
};

#endif
