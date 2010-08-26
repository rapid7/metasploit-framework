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
#ifndef __ASM_SH_TIMER_H
#define __ASM_SH_TIMER_H

#include <linux/sysdev.h>
#include <linux/clocksource.h>
#include <cpu/timer.h>

struct sys_timer_ops {
 int (*init)(void);
 int (*start)(void);
 int (*stop)(void);
 cycle_t (*read)(void);
};

struct sys_timer {
 const char *name;

 struct sys_device dev;
 struct sys_timer_ops *ops;
};

#define TICK_SIZE (tick_nsec / 1000)

struct sys_timer *get_sys_timer(void);

#endif
