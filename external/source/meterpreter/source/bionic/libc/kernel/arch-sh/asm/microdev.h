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
#ifndef __ASM_SH_MICRODEV_H
#define __ASM_SH_MICRODEV_H

#define MICRODEV_FPGA_INTC_BASE 0xa6110000ul  
#define MICRODEV_FPGA_INTENB_REG (MICRODEV_FPGA_INTC_BASE+0ul)  
#define MICRODEV_FPGA_INTDSB_REG (MICRODEV_FPGA_INTC_BASE+8ul)  
#define MICRODEV_FPGA_INTC_MASK(n) (1ul<<(n))  
#define MICRODEV_FPGA_INTPRI_REG(n) (MICRODEV_FPGA_INTC_BASE+0x10+((n)/8)*8) 
#define MICRODEV_FPGA_INTPRI_LEVEL(n,x) ((x)<<(((n)%8)*4))  
#define MICRODEV_FPGA_INTPRI_MASK(n) (MICRODEV_FPGA_INTPRI_LEVEL((n),0xful))  
#define MICRODEV_FPGA_INTSRC_REG (MICRODEV_FPGA_INTC_BASE+0x30ul)  
#define MICRODEV_FPGA_INTREQ_REG (MICRODEV_FPGA_INTC_BASE+0x38ul)  

#define MICRODEV_LINUX_IRQ_KEYBOARD 1  
#define MICRODEV_LINUX_IRQ_SERIAL1 2  
#define MICRODEV_LINUX_IRQ_ETHERNET 3  
#define MICRODEV_LINUX_IRQ_SERIAL2 4  
#define MICRODEV_LINUX_IRQ_USB_HC 7  
#define MICRODEV_LINUX_IRQ_MOUSE 12  
#define MICRODEV_LINUX_IRQ_IDE2 13  
#define MICRODEV_LINUX_IRQ_IDE1 14  

#define MICRODEV_FPGA_IRQ_KEYBOARD 1  
#define MICRODEV_FPGA_IRQ_SERIAL1 3  
#define MICRODEV_FPGA_IRQ_SERIAL2 4  
#define MICRODEV_FPGA_IRQ_MOUSE 12  
#define MICRODEV_FPGA_IRQ_IDE1 14  
#define MICRODEV_FPGA_IRQ_IDE2 15  
#define MICRODEV_FPGA_IRQ_USB_HC 16  
#define MICRODEV_FPGA_IRQ_ETHERNET 18  

#define MICRODEV_IRQ_PCI_INTA 8
#define MICRODEV_IRQ_PCI_INTB 9
#define MICRODEV_IRQ_PCI_INTC 10
#define MICRODEV_IRQ_PCI_INTD 11

#define __IO_PREFIX microdev
#include <asm/io_generic.h>

#endif
