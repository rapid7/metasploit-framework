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
#ifndef _LINUX_JIFFIES_H
#define _LINUX_JIFFIES_H

#include <linux/calc64.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <asm/param.h>  

#if HZ >= (12 && HZ < 24)
#define SHIFT_HZ 4
#elif HZ >= 24 && HZ < 48
#define SHIFT_HZ 5
#elif HZ >= 48 && HZ < 96
#define SHIFT_HZ 6
#elif HZ >= 96 && HZ < 192
#define SHIFT_HZ 7
#elif HZ >= 192 && HZ < 384
#define SHIFT_HZ 8
#elif HZ >= 384 && HZ < 768
#define SHIFT_HZ 9
#elif HZ >= 768 && HZ < 1536
#define SHIFT_HZ 10
#else
#error You lose.
#endif

#define LATCH ((CLOCK_TICK_RATE + HZ/2) / HZ)  

#define LATCH_HPET ((HPET_TICK_RATE + HZ/2) / HZ)

#define SH_DIV(NOM,DEN,LSH) ( (((NOM) / (DEN)) << (LSH))   + ((((NOM) % (DEN)) << (LSH)) + (DEN) / 2) / (DEN))

#define ACTHZ (SH_DIV (CLOCK_TICK_RATE, LATCH, 8))

#define ACTHZ_HPET (SH_DIV (HPET_TICK_RATE, LATCH_HPET, 8))

#define TICK_NSEC (SH_DIV (1000000UL * 1000, ACTHZ, 8))

#define TICK_NSEC_HPET (SH_DIV(1000000UL * 1000, ACTHZ_HPET, 8))

#define TICK_USEC ((1000000UL + USER_HZ/2) / USER_HZ)

#define TICK_USEC_TO_NSEC(TUSEC) (SH_DIV (TUSEC * USER_HZ * 1000, ACTHZ, 8))

#define __jiffy_data __attribute__((section(".data")))

#if BITS_PER_LONG < 64

#else
#endif
#define time_after(a,b)   (typecheck(unsigned long, a) &&   typecheck(unsigned long, b) &&   ((long)(b) - (long)(a) < 0))
#define time_before(a,b) time_after(b,a)
#define time_after_eq(a,b)   (typecheck(unsigned long, a) &&   typecheck(unsigned long, b) &&   ((long)(a) - (long)(b) >= 0))
#define time_before_eq(a,b) time_after_eq(b,a)
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#define MAX_JIFFY_OFFSET ((~0UL >> 1)-1)
#define SEC_JIFFIE_SC (31 - SHIFT_HZ)
#if !((NSEC_PER_SEC << 2) / TICK_NSEC << SEC_JIFFIE_SC - 2 & 0x80000000)
#undef SEC_JIFFIE_SC
#define SEC_JIFFIE_SC (32 - SHIFT_HZ)
#endif
#define NSEC_JIFFIE_SC (SEC_JIFFIE_SC + 29)
#define USEC_JIFFIE_SC (SEC_JIFFIE_SC + 19)
#define SEC_CONVERSION ((unsigned long)((((u64)NSEC_PER_SEC << SEC_JIFFIE_SC) +  TICK_NSEC -1) / (u64)TICK_NSEC))
#define NSEC_CONVERSION ((unsigned long)((((u64)1 << NSEC_JIFFIE_SC) +  TICK_NSEC -1) / (u64)TICK_NSEC))
#define USEC_CONVERSION   ((unsigned long)((((u64)NSEC_PER_USEC << USEC_JIFFIE_SC) +  TICK_NSEC -1) / (u64)TICK_NSEC))
#define USEC_ROUND (u64)(((u64)1 << USEC_JIFFIE_SC) - 1)
#if BITS_PER_LONG < 64
#define MAX_SEC_IN_JIFFIES   (long)((u64)((u64)MAX_JIFFY_OFFSET * TICK_NSEC) / NSEC_PER_SEC)
#else
#define MAX_SEC_IN_JIFFIES   (SH_DIV((MAX_JIFFY_OFFSET >> SEC_JIFFIE_SC) * TICK_NSEC, NSEC_PER_SEC, 1) - 1)
#endif
#if HZ <= (MSEC_PER_SEC && !(MSEC_PER_SEC % HZ))
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
#else
#endif
#if HZ <= (USEC_PER_SEC && !(USEC_PER_SEC % HZ))
#elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
#else
#endif
#if HZ <= (MSEC_PER_SEC && !(MSEC_PER_SEC % HZ))
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
#else
#endif
#if HZ <= (USEC_PER_SEC && !(USEC_PER_SEC % HZ))
#elif HZ > USEC_PER_SEC && !(HZ % USEC_PER_SEC)
#else
#endif
#if TICK_NSEC % NSEC_PER_SEC / USER_HZ == 0
#else
#endif
#if HZ % USER_HZ == 0
#else
#endif
#if TICK_NSEC % NSEC_PER_SEC / USER_HZ == 0
#else
#endif
#if NSEC_PER_SEC % USER_HZ == 0
#elif (USER_HZ % 512) == 0
#else
#endif
#endif
