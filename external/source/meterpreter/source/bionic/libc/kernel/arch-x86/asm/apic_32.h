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
#ifndef __ASM_APIC_H
#define __ASM_APIC_H

#include <linux/pm.h>
#include <linux/delay.h>
#include <asm/fixmap.h>
#include <asm/apicdef.h>
#include <asm/processor.h>
#include <asm/system.h>

#define Dprintk(x...)

#define APIC_QUIET 0
#define APIC_VERBOSE 1
#define APIC_DEBUG 2

#define apic_printk(v, s, a...) do {   if ((v) <= apic_verbosity)   printk(s, ##a);   } while (0)

#define local_apic_timer_c2_ok 1
#endif
