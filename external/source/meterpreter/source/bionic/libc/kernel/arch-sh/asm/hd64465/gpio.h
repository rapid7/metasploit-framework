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
#ifndef _ASM_SH_HD64465_GPIO_
#define _ASM_SH_HD64465_GPIO_ 1

#include <asm/hd64465.h>

#define HD64465_GPIO_PORTPIN(port,pin) (((port)-'A')<<3|(pin))

#define HD64465_GPIO_FUNCTION2 0  
#define HD64465_GPIO_OUT 1  
#define HD64465_GPIO_IN_PULLUP 2  
#define HD64465_GPIO_IN 3  

#define HD64465_GPIO_FALLING 0
#define HD64465_GPIO_RISING 1

#endif
