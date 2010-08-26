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
#ifndef __ARM_MTD_XIP_H__
#define __ARM_MTD_XIP_H__

#include <asm/hardware.h>
#include <asm/arch/mtd-xip.h>

#define xip_iprefetch() do { asm volatile (".rep 8; nop; .endr"); } while (0)

#endif
