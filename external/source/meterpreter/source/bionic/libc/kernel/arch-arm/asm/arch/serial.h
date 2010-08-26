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
#ifndef __ASM_ARCH_SERIAL_H
#define __ASM_ARCH_SERIAL_H

#define OMAP_MAX_NR_PORTS 3
#define OMAP1510_BASE_BAUD (12000000/16)
#define OMAP16XX_BASE_BAUD (48000000/16)

#define is_omap_port(p) ({int __ret = 0;   if (p == IO_ADDRESS(OMAP_UART1_BASE) ||   p == IO_ADDRESS(OMAP_UART2_BASE) ||   p == IO_ADDRESS(OMAP_UART3_BASE))   __ret = 1;   __ret;   })

#endif
