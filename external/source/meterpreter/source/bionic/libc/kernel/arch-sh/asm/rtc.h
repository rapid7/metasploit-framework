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
#ifndef _ASM_RTC_H
#define _ASM_RTC_H

#define RTC_CAP_4_DIGIT_YEAR (1 << 0)

struct sh_rtc_platform_info {
 unsigned long capabilities;
};

#include <cpu/rtc.h>

#endif
