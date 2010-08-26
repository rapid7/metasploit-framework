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
#ifndef __ASM_SH_SMC37C93X_H
#define __ASM_SH_SMC37C93X_H

#define FDC_PRIMARY_BASE 0x3f0
#define IDE1_PRIMARY_BASE 0x1f0
#define IDE1_SECONDARY_BASE 0x170
#define PARPORT_PRIMARY_BASE 0x378
#define COM1_PRIMARY_BASE 0x2f8
#define COM2_PRIMARY_BASE 0x3f8
#define RTC_PRIMARY_BASE 0x070
#define KBC_PRIMARY_BASE 0x060
#define AUXIO_PRIMARY_BASE 0x000  

#define LDN_FDC 0
#define LDN_IDE1 1
#define LDN_IDE2 2
#define LDN_PARPORT 3
#define LDN_COM1 4
#define LDN_COM2 5
#define LDN_RTC 6
#define LDN_KBC 7
#define LDN_AUXIO 8

#define CONFIG_PORT 0x3f0
#define INDEX_PORT CONFIG_PORT
#define DATA_PORT 0x3f1
#define CONFIG_ENTER 0x55
#define CONFIG_EXIT 0xaa

#define CURRENT_LDN_INDEX 0x07
#define POWER_CONTROL_INDEX 0x22
#define ACTIVATE_INDEX 0x30
#define IO_BASE_HI_INDEX 0x60
#define IO_BASE_LO_INDEX 0x61
#define IRQ_SELECT_INDEX 0x70
#define DMA_SELECT_INDEX 0x74

#define GPIO46_INDEX 0xc6
#define GPIO47_INDEX 0xc7

#define UART_RBR 0x0  
#define UART_THR 0x0  
#define UART_IER 0x2  
#define UART_IIR 0x4  
#define UART_FCR 0x4  
#define UART_LCR 0x6  
#define UART_MCR 0x8  
#define UART_LSR 0xa  
#define UART_MSR 0xc  
#define UART_SCR 0xe  
#define UART_DLL 0x0  
#define UART_DLM 0x2  

#ifndef __ASSEMBLY__
typedef struct uart_reg {
 volatile __u16 rbr;
 volatile __u16 ier;
 volatile __u16 iir;
 volatile __u16 lcr;
 volatile __u16 mcr;
 volatile __u16 lsr;
 volatile __u16 msr;
 volatile __u16 scr;
} uart_reg;
#endif

#define thr rbr
#define tcr iir

#define dll rbr
#define dlm ier
#define fcr iir

#define IER_ERDAI 0x0100  
#define IER_ETHREI 0x0200  
#define IER_ELSI 0x0400  
#define IER_EMSI 0x0800  

#define IIR_IP 0x0100  
#define IIR_IIB0 0x0200  
#define IIR_IIB1 0x0400  
#define IIR_IIB2 0x0800  
#define IIR_FIFO 0xc000  

#define FCR_FEN 0x0100  
#define FCR_RFRES 0x0200  
#define FCR_TFRES 0x0400  
#define FCR_DMA 0x0800  
#define FCR_RTL 0x4000  
#define FCR_RTM 0x8000  

#define LCR_WLS0 0x0100  
#define LCR_WLS1 0x0200  
#define LCR_STB 0x0400  
#define LCR_PEN 0x0800  
#define LCR_EPS 0x1000  
#define LCR_SP 0x2000  
#define LCR_SB 0x4000  
#define LCR_DLAB 0x8000  

#define MCR_DTR 0x0100  
#define MCR_RTS 0x0200  
#define MCR_OUT1 0x0400  
#define MCR_IRQEN 0x0800  
#define MCR_LOOP 0x1000  

#define LSR_DR 0x0100  
#define LSR_OE 0x0200  
#define LSR_PE 0x0400  
#define LSR_FE 0x0800  
#define LSR_BI 0x1000  
#define LSR_THRE 0x2000  
#define LSR_TEMT 0x4000  
#define LSR_FIFOE 0x8000  

#define MSR_DCTS 0x0100  
#define MSR_DDSR 0x0200  
#define MSR_TERI 0x0400  
#define MSR_DDCD 0x0800  
#define MSR_CTS 0x1000  
#define MSR_DSR 0x2000  
#define MSR_RI 0x4000  
#define MSR_DCD 0x8000  

#define UART_CLK (1843200)  
#define UART_BAUD(x) (UART_CLK / (16 * (x)))

#define RTC_SECONDS 0
#define RTC_SECONDS_ALARM 1
#define RTC_MINUTES 2
#define RTC_MINUTES_ALARM 3
#define RTC_HOURS 4
#define RTC_HOURS_ALARM 5
#define RTC_DAY_OF_WEEK 6
#define RTC_DAY_OF_MONTH 7
#define RTC_MONTH 8
#define RTC_YEAR 9
#define RTC_FREQ_SELECT 10
#define RTC_UIP 0x80
#define RTC_DIV_CTL 0x70

#define RTC_OSC_ENABLE 0x20
#define RTC_OSC_DISABLE 0x00
#define RTC_CONTROL 11
#define RTC_SET 0x80
#define RTC_PIE 0x40
#define RTC_AIE 0x20
#define RTC_UIE 0x10
#define RTC_SQWE 0x08
#define RTC_DM_BINARY 0x04
#define RTC_24H 0x02
#define RTC_DST_EN 0x01

#endif
