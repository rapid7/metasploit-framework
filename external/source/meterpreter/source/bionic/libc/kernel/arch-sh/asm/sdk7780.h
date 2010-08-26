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
#ifndef __ASM_SH_RENESAS_SDK7780_H
#define __ASM_SH_RENESAS_SDK7780_H

#include <asm/addrspace.h>

#define SE_AREA0_WIDTH 4  
#define PA_ROM 0xa0000000  
#define PA_ROM_SIZE 0x00400000  
#define PA_FROM 0xa0800000  
#define PA_FROM_SIZE 0x00400000  
#define PA_EXT1 0xa4000000
#define PA_EXT1_SIZE 0x04000000
#define PA_SDRAM 0xa8000000  
#define PA_SDRAM_SIZE 0x08000000

#define PA_EXT4 0xb0000000
#define PA_EXT4_SIZE 0x04000000
#define PA_EXT_USER PA_EXT4  

#define PA_PERIPHERAL PA_AREA5_IO

#define PA_RESERVED (PA_PERIPHERAL + 0)

#define PA_FPGA (PA_PERIPHERAL + 0x01000000)

#define PA_LAN (PA_PERIPHERAL + 0x01800000)

#define FPGA_SRSTR (PA_FPGA + 0x000)  
#define FPGA_IRQ0SR (PA_FPGA + 0x010)  
#define FPGA_IRQ0MR (PA_FPGA + 0x020)  
#define FPGA_BDMR (PA_FPGA + 0x030)  
#define FPGA_INTT0PRTR (PA_FPGA + 0x040)  
#define FPGA_INTT0SELR (PA_FPGA + 0x050)  
#define FPGA_INTT1POLR (PA_FPGA + 0x060)  
#define FPGA_NMIR (PA_FPGA + 0x070)  
#define FPGA_NMIMR (PA_FPGA + 0x080)  
#define FPGA_IRQR (PA_FPGA + 0x090)  
#define FPGA_IRQMR (PA_FPGA + 0x0A0)  
#define FPGA_SLEDR (PA_FPGA + 0x0B0)  
#define PA_LED FPGA_SLEDR
#define FPGA_MAPSWR (PA_FPGA + 0x0C0)  
#define FPGA_FPVERR (PA_FPGA + 0x0D0)  
#define FPGA_FPDATER (PA_FPGA + 0x0E0)  
#define FPGA_RSE (PA_FPGA + 0x100)  
#define FPGA_EASR (PA_FPGA + 0x110)  
#define FPGA_SPER (PA_FPGA + 0x120)  
#define FPGA_IMSR (PA_FPGA + 0x130)  
#define FPGA_PCIMR (PA_FPGA + 0x140)  
#define FPGA_DIPSWMR (PA_FPGA + 0x150)  
#define FPGA_FPODR (PA_FPGA + 0x160)  
#define FPGA_ATAESR (PA_FPGA + 0x170)  
#define FPGA_IRQPOLR (PA_FPGA + 0x180)  

#define SDK7780_NR_IRL 15

#define IRQ_CFCARD 14

#define IRQ_ETHERNET 6

#define __IO_PREFIX sdk7780
#include <asm/io_generic.h>

#endif
