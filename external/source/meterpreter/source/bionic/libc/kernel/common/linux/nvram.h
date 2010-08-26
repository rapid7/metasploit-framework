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
#ifndef _LINUX_NVRAM_H
#define _LINUX_NVRAM_H

#include <linux/ioctl.h>

#define NVRAM_INIT _IO('p', 0x40)  
#define NVRAM_SETCKS _IO('p', 0x41)  

#define NVRAM_FIRST_BYTE 14

#define NVRAM_OFFSET(x) ((x)-NVRAM_FIRST_BYTE)

#endif
