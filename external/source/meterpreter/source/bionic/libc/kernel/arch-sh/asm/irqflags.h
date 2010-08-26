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
#ifndef __ASM_SH_IRQFLAGS_H
#define __ASM_SH_IRQFLAGS_H

#include "irqflags_32.h"

#define raw_local_save_flags(flags)   do { (flags) = __raw_local_save_flags(); } while (0)

#define raw_local_irq_save(flags)   do { (flags) = __raw_local_irq_save(); } while (0)
#endif
