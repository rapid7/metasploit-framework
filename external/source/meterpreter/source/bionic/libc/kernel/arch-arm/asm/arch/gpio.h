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
#ifndef __ASM_ARCH_OMAP_GPIO_H
#define __ASM_ARCH_OMAP_GPIO_H

#include <asm/hardware.h>
#include <asm/arch/irqs.h>
#include <asm/io.h>

#define OMAP_MPUIO_BASE (void __iomem *)0xfffb5000

#define OMAP_MPUIO_INPUT_LATCH 0x00
#define OMAP_MPUIO_OUTPUT 0x04
#define OMAP_MPUIO_IO_CNTL 0x08
#define OMAP_MPUIO_KBR_LATCH 0x10
#define OMAP_MPUIO_KBC 0x14
#define OMAP_MPUIO_GPIO_EVENT_MODE 0x18
#define OMAP_MPUIO_GPIO_INT_EDGE 0x1c
#define OMAP_MPUIO_KBD_INT 0x20
#define OMAP_MPUIO_GPIO_INT 0x24
#define OMAP_MPUIO_KBD_MASKIT 0x28
#define OMAP_MPUIO_GPIO_MASKIT 0x2c
#define OMAP_MPUIO_GPIO_DEBOUNCING 0x30
#define OMAP_MPUIO_LATCH 0x34

#define OMAP_MPUIO(nr) (OMAP_MAX_GPIO_LINES + (nr))
#define OMAP_GPIO_IS_MPUIO(nr) ((nr) >= OMAP_MAX_GPIO_LINES)

#define OMAP_GPIO_IRQ(nr) (OMAP_GPIO_IS_MPUIO(nr) ?   IH_MPUIO_BASE + ((nr) & 0x0f) :   IH_GPIO_BASE + (nr))

struct omap_machine_gpio_bank {
 int start;
 int end;

 void (*set_gpio_direction)(int gpio, int is_input);
 void (*set_gpio_dataout)(int gpio, int enable);
 int (*get_gpio_datain)(int gpio);
};

#endif
