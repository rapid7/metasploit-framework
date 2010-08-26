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
#ifndef _ASM_MC146818RTC_H
#define _ASM_MC146818RTC_H

#include <asm/io.h>
#include <asm/system.h>
#include <asm/processor.h>
#include <linux/mc146818rtc.h>

#ifndef RTC_PORT
#define RTC_PORT(x) (0x70 + (x))
#define RTC_ALWAYS_BCD 1  
#endif

#ifdef __HAVE_ARCH_CMPXCHG

#include <linux/smp.h>

#define lock_cmos_prefix(reg)   do {   unsigned long cmos_flags;   local_irq_save(cmos_flags);   lock_cmos(reg)
#define lock_cmos_suffix(reg)   unlock_cmos();   local_irq_restore(cmos_flags);   } while (0)
#else
#define lock_cmos_prefix(reg) do {} while (0)
#define lock_cmos_suffix(reg) do {} while (0)
#define lock_cmos(reg)
#define unlock_cmos()
#define do_i_have_lock_cmos() 0
#define current_lock_cmos_reg() 0
#endif
#define CMOS_READ(addr) rtc_cmos_read(addr)
#define CMOS_WRITE(val, addr) rtc_cmos_write(val, addr)

#define RTC_IRQ 8

#endif
