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
#ifndef _IP6T_HL_H
#define _IP6T_HL_H

enum {
 IP6T_HL_SET = 0,
 IP6T_HL_INC,
 IP6T_HL_DEC
};

#define IP6T_HL_MAXMODE IP6T_HL_DEC

struct ip6t_HL_info {
 u_int8_t mode;
 u_int8_t hop_limit;
};

#endif
