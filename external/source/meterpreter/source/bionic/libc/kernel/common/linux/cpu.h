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
#ifndef _LINUX_CPU_H_
#define _LINUX_CPU_H_

#include <linux/sysdev.h>
#include <linux/node.h>
#include <linux/compiler.h>
#include <linux/cpumask.h>
#include <asm/semaphore.h>

struct cpu {
 int node_id;
 int no_control;
 struct sys_device sysdev;
};

struct notifier_block;

#define lock_cpu_hotplug() do { } while (0)
#define unlock_cpu_hotplug() do { } while (0)
#define lock_cpu_hotplug_interruptible() 0
#define hotcpu_notifier(fn, pri) do { } while (0)
#define register_hotcpu_notifier(nb) do { } while (0)
#define unregister_hotcpu_notifier(nb) do { } while (0)

#endif
