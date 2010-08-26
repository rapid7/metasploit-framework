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
#ifndef _MC146818RTC_H
#define _MC146818RTC_H

#include <asm/io.h>
#include <linux/rtc.h>  
#include <asm/mc146818rtc.h>  

#define RTC_SECONDS 0
#define RTC_SECONDS_ALARM 1
#define RTC_MINUTES 2
#define RTC_MINUTES_ALARM 3
#define RTC_HOURS 4
#define RTC_HOURS_ALARM 5

#define RTC_ALARM_DONT_CARE 0xC0

#define RTC_DAY_OF_WEEK 6
#define RTC_DAY_OF_MONTH 7
#define RTC_MONTH 8
#define RTC_YEAR 9

#define RTC_REG_A 10
#define RTC_REG_B 11
#define RTC_REG_C 12
#define RTC_REG_D 13

#define RTC_FREQ_SELECT RTC_REG_A

#define RTC_UIP 0x80
#define RTC_DIV_CTL 0x70

#define RTC_REF_CLCK_4MHZ 0x00
#define RTC_REF_CLCK_1MHZ 0x10
#define RTC_REF_CLCK_32KHZ 0x20

#define RTC_DIV_RESET1 0x60
#define RTC_DIV_RESET2 0x70

#define RTC_RATE_SELECT 0x0F

#define RTC_CONTROL RTC_REG_B
#define RTC_SET 0x80  
#define RTC_PIE 0x40  
#define RTC_AIE 0x20  
#define RTC_UIE 0x10  
#define RTC_SQWE 0x08  
#define RTC_DM_BINARY 0x04  
#define RTC_24H 0x02  
#define RTC_DST_EN 0x01  

#define RTC_INTR_FLAGS RTC_REG_C

#define RTC_IRQF 0x80  
#define RTC_PF 0x40
#define RTC_AF 0x20
#define RTC_UF 0x10

#define RTC_VALID RTC_REG_D
#define RTC_VRT 0x80  

#ifndef ARCH_RTC_LOCATION

#define RTC_IO_EXTENT 0x8
#define RTC_IOMAPPED 1  

#endif

#endif
