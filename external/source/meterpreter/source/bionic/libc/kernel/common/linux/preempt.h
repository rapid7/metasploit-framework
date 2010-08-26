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
#ifndef __LINUX_PREEMPT_H
#define __LINUX_PREEMPT_H

#include <linux/thread_info.h>
#include <linux/linkage.h>

#define add_preempt_count(val) do { preempt_count() += (val); } while (0)
#define sub_preempt_count(val) do { preempt_count() -= (val); } while (0)

#define inc_preempt_count() add_preempt_count(1)
#define dec_preempt_count() sub_preempt_count(1)

#define preempt_count() (current_thread_info()->preempt_count)

#define preempt_disable() do { } while (0)
#define preempt_enable_no_resched() do { } while (0)
#define preempt_enable() do { } while (0)
#define preempt_check_resched() do { } while (0)

#endif
