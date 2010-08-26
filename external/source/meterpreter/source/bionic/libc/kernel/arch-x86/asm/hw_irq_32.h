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
#ifndef _ASM_HW_IRQ_H
#define _ASM_HW_IRQ_H

#include <linux/profile.h>
#include <asm/atomic.h>
#include <asm/irq.h>
#include <asm/sections.h>

#define NMI_VECTOR 0x02

#define IO_APIC_IRQ(x) (((x) >= 16) || ((1<<(x)) & io_apic_irqs))

#endif
