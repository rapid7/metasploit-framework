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
#ifndef __ASM_ARM_ARCH_IO_H
#define __ASM_ARM_ARCH_IO_H

#include <asm/hardware.h>

#define IO_SPACE_LIMIT 0xffffffff

#define __io(a) ((void __iomem *)(PCIO_BASE + (a)))
#define __mem_pci(a) (a)

#define PCIO_BASE 0

#ifndef __ASSEMBLER__

#define omap_readb(a) (*(volatile unsigned char *)IO_ADDRESS(a))
#define omap_readw(a) (*(volatile unsigned short *)IO_ADDRESS(a))
#define omap_readl(a) (*(volatile unsigned int *)IO_ADDRESS(a))

#define omap_writeb(v,a) (*(volatile unsigned char *)IO_ADDRESS(a) = (v))
#define omap_writew(v,a) (*(volatile unsigned short *)IO_ADDRESS(a) = (v))
#define omap_writel(v,a) (*(volatile unsigned int *)IO_ADDRESS(a) = (v))

typedef struct { volatile u16 offset[256]; } __regbase16;
#define __REGV16(vaddr) ((__regbase16 *)((vaddr)&~0xff))   ->offset[((vaddr)&0xff)>>1]
#define __REG16(paddr) __REGV16(io_p2v(paddr))

typedef struct { volatile u8 offset[4096]; } __regbase8;
#define __REGV8(vaddr) ((__regbase8 *)((vaddr)&~4095))   ->offset[((vaddr)&4095)>>0]
#define __REG8(paddr) __REGV8(io_p2v(paddr))

typedef struct { volatile u32 offset[4096]; } __regbase32;
#define __REGV32(vaddr) ((__regbase32 *)((vaddr)&~4095))   ->offset[((vaddr)&4095)>>2]
#define __REG32(paddr) __REGV32(io_p2v(paddr))

#else

#define __REG8(paddr) io_p2v(paddr)
#define __REG16(paddr) io_p2v(paddr)
#define __REG32(paddr) io_p2v(paddr)

#endif

#endif
