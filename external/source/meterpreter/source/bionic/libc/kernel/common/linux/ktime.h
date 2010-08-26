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
#ifndef _LINUX_KTIME_H
#define _LINUX_KTIME_H

#include <linux/time.h>
#include <linux/jiffies.h>

typedef union {
 s64 tv64;
#if BITS_PER_LONG != (64 && !defined(CONFIG_KTIME_SCALAR))
 struct {
#ifdef __BIG_ENDIAN
 s32 sec, nsec;
#else
 s32 nsec, sec;
#endif
 } tv;
#endif
} ktime_t;

#define KTIME_MAX ((s64)~((u64)1 << 63))
#define KTIME_SEC_MAX (KTIME_MAX / NSEC_PER_SEC)

#if BITS_PER_LONG == 64

#if BITS_PER_LONG == 64
#endif
#define ktime_sub(lhs, rhs)   ({ (ktime_t){ .tv64 = (lhs).tv64 - (rhs).tv64 }; })
#define ktime_add(lhs, rhs)   ({ (ktime_t){ .tv64 = (lhs).tv64 + (rhs).tv64 }; })
#define ktime_add_ns(kt, nsval)   ({ (ktime_t){ .tv64 = (kt).tv64 + (nsval) }; })
#define ktime_to_timespec(kt) ns_to_timespec((kt).tv64)
#define ktime_to_timeval(kt) ns_to_timeval((kt).tv64)
#define ktime_to_ns(kt) ((kt).tv64)
#else

#endif
#define KTIME_REALTIME_RES (ktime_t){ .tv64 = TICK_NSEC }
#define KTIME_MONOTONIC_RES (ktime_t){ .tv64 = TICK_NSEC }

#define ktime_get_real_ts(ts) getnstimeofday(ts)

#endif
