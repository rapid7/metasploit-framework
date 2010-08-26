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
#ifndef __ASM_ARCH_OMAP24XX_H
#define __ASM_ARCH_OMAP24XX_H

#define L4_24XX_BASE 0x48000000
#define L3_24XX_BASE 0x68000000

#define OMAP24XX_IC_BASE (L4_24XX_BASE + 0xfe000)
#define VA_IC_BASE IO_ADDRESS(OMAP24XX_IC_BASE)
#define OMAP24XX_IVA_INTC_BASE 0x40000000
#define IRQ_SIR_IRQ 0x0040

#define OMAP24XX_32KSYNCT_BASE (L4_24XX_BASE + 0x4000)
#define OMAP24XX_PRCM_BASE (L4_24XX_BASE + 0x8000)
#define OMAP24XX_SDRC_BASE (L3_24XX_BASE + 0x9000)

#define OMAP242X_CONTROL_STATUS (L4_24XX_BASE + 0x2f8)

#endif

