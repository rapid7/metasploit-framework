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
#ifndef __ASM_SH_IRQ_H
#define __ASM_SH_IRQ_H

#include <asm/machvec.h>

#define NR_IRQS 256

#define evt2irq(evt) (((evt) >> 5) - 16)
#define irq2evt(irq) (((irq) + 16) << 5)

#define irq_canonicalize(irq) (irq)
#define irq_demux(irq) sh_mv.mv_irq_demux(irq)
#define irq_ctx_init(cpu) do { } while (0)
#define irq_ctx_exit(cpu) do { } while (0)
#endif
