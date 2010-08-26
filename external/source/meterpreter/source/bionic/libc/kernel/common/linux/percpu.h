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
#ifndef __LINUX_PERCPU_H
#define __LINUX_PERCPU_H
#include <linux/spinlock.h>  
#include <linux/slab.h>  
#include <linux/smp.h>
#include <linux/string.h>  
#include <asm/percpu.h>

#ifndef PERCPU_ENOUGH_ROOM
#define PERCPU_ENOUGH_ROOM 32768
#endif

#define get_cpu_var(var) (*({ preempt_disable(); &__get_cpu_var(var); }))
#define put_cpu_var(var) preempt_enable()

#define per_cpu_ptr(ptr, cpu) ({ (void)(cpu); (ptr); })

#define alloc_percpu(type) ((type *)(__alloc_percpu(sizeof(type))))
#endif
