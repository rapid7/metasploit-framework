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
#ifndef _XT_COMMENT_H
#define _XT_COMMENT_H

#define XT_MAX_COMMENT_LEN 256

struct xt_comment_info {
 unsigned char comment[XT_MAX_COMMENT_LEN];
};

#endif
