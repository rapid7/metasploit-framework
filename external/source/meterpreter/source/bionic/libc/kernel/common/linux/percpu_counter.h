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
#ifndef _LINUX_PERCPU_COUNTER_H
#define _LINUX_PERCPU_COUNTER_H

#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/threads.h>
#include <linux/percpu.h>
#include <linux/types.h>

struct percpu_counter {
 s64 count;
};

#endif
