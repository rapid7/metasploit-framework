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
#ifndef _XT_STATISTIC_H
#define _XT_STATISTIC_H

enum xt_statistic_mode {
 XT_STATISTIC_MODE_RANDOM,
 XT_STATISTIC_MODE_NTH,
 __XT_STATISTIC_MODE_MAX
};
#define XT_STATISTIC_MODE_MAX (__XT_STATISTIC_MODE_MAX - 1)

enum xt_statistic_flags {
 XT_STATISTIC_INVERT = 0x1,
};
#define XT_STATISTIC_MASK 0x1

struct xt_statistic_info {
 u_int16_t mode;
 u_int16_t flags;
 union {
 struct {
 u_int32_t probability;
 } random;
 struct {
 u_int32_t every;
 u_int32_t packet;
 u_int32_t count;
 } nth;
 } u;
 struct xt_statistic_info *master __attribute__((aligned(8)));
};

#endif
