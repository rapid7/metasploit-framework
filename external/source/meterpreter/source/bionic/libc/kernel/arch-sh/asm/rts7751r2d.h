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
#ifndef __ASM_SH_RENESAS_RTS7751R2D_H
#define __ASM_SH_RENESAS_RTS7751R2D_H

#define PA_BCR 0xa4000000  
#define PA_IRLMON 0xa4000002  
#define PA_CFCTL 0xa4000004  
#define PA_CFPOW 0xa4000006  
#define PA_DISPCTL 0xa4000008  
#define PA_SDMPOW 0xa400000a  
#define PA_RTCCE 0xa400000c  
#define PA_PCICD 0xa400000e  
#define PA_VOYAGERRTS 0xa4000020  

#define PA_R2D1_AXRST 0xa4000022  
#define PA_R2D1_CFRST 0xa4000024  
#define PA_R2D1_ADMRTS 0xa4000026  
#define PA_R2D1_EXTRST 0xa4000028  
#define PA_R2D1_CFCDINTCLR 0xa400002a  

#define PA_R2DPLUS_CFRST 0xa4000022  
#define PA_R2DPLUS_ADMRTS 0xa4000024  
#define PA_R2DPLUS_EXTRST 0xa4000026  
#define PA_R2DPLUS_CFCDINTCLR 0xa4000028  
#define PA_R2DPLUS_KEYCTLCLR 0xa400002a  

#define PA_POWOFF 0xa4000030  
#define PA_VERREG 0xa4000032  
#define PA_INPORT 0xa4000034  
#define PA_OUTPORT 0xa4000036  
#define PA_BVERREG 0xa4000038  

#define PA_AX88796L 0xaa000400  
#define PA_VOYAGER 0xab000000  
#define PA_IDE_OFFSET 0x1f0  
#define AX88796L_IO_BASE 0x1000  

#define IRLCNTR1 (PA_BCR + 0)  

#define R2D_FPGA_IRQ_BASE 100

#define IRQ_VOYAGER (R2D_FPGA_IRQ_BASE + 0)
#define IRQ_EXT (R2D_FPGA_IRQ_BASE + 1)
#define IRQ_TP (R2D_FPGA_IRQ_BASE + 2)
#define IRQ_RTC_T (R2D_FPGA_IRQ_BASE + 3)
#define IRQ_RTC_A (R2D_FPGA_IRQ_BASE + 4)
#define IRQ_SDCARD (R2D_FPGA_IRQ_BASE + 5)
#define IRQ_CF_CD (R2D_FPGA_IRQ_BASE + 6)
#define IRQ_CF_IDE (R2D_FPGA_IRQ_BASE + 7)
#define IRQ_AX88796 (R2D_FPGA_IRQ_BASE + 8)
#define IRQ_KEY (R2D_FPGA_IRQ_BASE + 9)
#define IRQ_PCI_INTA (R2D_FPGA_IRQ_BASE + 10)
#define IRQ_PCI_INTB (R2D_FPGA_IRQ_BASE + 11)
#define IRQ_PCI_INTC (R2D_FPGA_IRQ_BASE + 12)
#define IRQ_PCI_INTD (R2D_FPGA_IRQ_BASE + 13)

#endif
