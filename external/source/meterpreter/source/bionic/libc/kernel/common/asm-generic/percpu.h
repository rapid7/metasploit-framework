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
#ifndef _ASM_GENERIC_PERCPU_H_
#define _ASM_GENERIC_PERCPU_H_
#include <linux/compiler.h>

#define __GENERIC_PER_CPU

#define DEFINE_PER_CPU(type, name)   __typeof__(type) per_cpu__##name

#define per_cpu(var, cpu) (*((void)(cpu), &per_cpu__##var))
#define __get_cpu_var(var) per_cpu__##var
#define __raw_get_cpu_var(var) per_cpu__##var

#define DECLARE_PER_CPU(type, name) extern __typeof__(type) per_cpu__##name

#define EXPORT_PER_CPU_SYMBOL(var) EXPORT_SYMBOL(per_cpu__##var)
#define EXPORT_PER_CPU_SYMBOL_GPL(var) EXPORT_SYMBOL_GPL(per_cpu__##var)

#endif
