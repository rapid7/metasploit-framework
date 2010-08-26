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
#ifndef _XT_CONNBYTES_H
#define _XT_CONNBYTES_H

enum xt_connbytes_what {
 XT_CONNBYTES_PKTS,
 XT_CONNBYTES_BYTES,
 XT_CONNBYTES_AVGPKT,
};

enum xt_connbytes_direction {
 XT_CONNBYTES_DIR_ORIGINAL,
 XT_CONNBYTES_DIR_REPLY,
 XT_CONNBYTES_DIR_BOTH,
};

struct xt_connbytes_info
{
 struct {
 aligned_u64 from;
 aligned_u64 to;
 } count;
 u_int8_t what;
 u_int8_t direction;
};
#endif
