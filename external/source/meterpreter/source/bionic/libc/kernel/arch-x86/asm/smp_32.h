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
#ifndef __ASM_SMP_H
#define __ASM_SMP_H

#ifndef __ASSEMBLY__
#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/cpumask.h>
#endif

#define BAD_APICID 0xFFu

#define safe_smp_processor_id() 0
#define cpu_physical_id(cpu) boot_cpu_physical_apicid

#define NO_PROC_ID 0xFF  

#ifndef __ASSEMBLY__

#define hard_smp_processor_id() 0

#endif

#endif
