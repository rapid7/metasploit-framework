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
#ifndef _LINUX_IRQRETURN_H
#define _LINUX_IRQRETURN_H

typedef int irqreturn_t;

#define IRQ_NONE (0)
#define IRQ_HANDLED (1)
#define IRQ_RETVAL(x) ((x) != 0)

#endif
