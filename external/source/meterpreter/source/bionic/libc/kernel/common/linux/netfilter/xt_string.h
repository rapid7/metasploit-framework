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
#ifndef _XT_STRING_H
#define _XT_STRING_H

#define XT_STRING_MAX_PATTERN_SIZE 128
#define XT_STRING_MAX_ALGO_NAME_SIZE 16

struct xt_string_info
{
 u_int16_t from_offset;
 u_int16_t to_offset;
 char algo[XT_STRING_MAX_ALGO_NAME_SIZE];
 char pattern[XT_STRING_MAX_PATTERN_SIZE];
 u_int8_t patlen;
 u_int8_t invert;
 struct ts_config __attribute__((aligned(8))) *config;
};

#endif
