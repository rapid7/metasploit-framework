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
#ifndef __ASM_SH_PUSH_SWITCH_H
#define __ASM_SH_PUSH_SWITCH_H

#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/platform_device.h>

struct push_switch {

 unsigned int state:1;

 struct timer_list debounce;

 struct work_struct work;

 struct platform_device *pdev;
};

struct push_switch_platform_info {

 irqreturn_t (*irq_handler)(int irq, void *data);

 unsigned int irq_flags;

 unsigned int bit;

 const char *name;
};

#endif
