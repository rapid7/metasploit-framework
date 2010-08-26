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
#ifndef __ASM_SH_ILSEL_H
#define __ASM_SH_ILSEL_H

typedef enum {
 ILSEL_NONE,
 ILSEL_LAN,
 ILSEL_USBH_I,
 ILSEL_USBH_S,
 ILSEL_USBH_V,
 ILSEL_RTC,
 ILSEL_USBP_I,
 ILSEL_USBP_S,
 ILSEL_USBP_V,
 ILSEL_KEY,

 ILSEL_FPGA0,
 ILSEL_FPGA1,
 ILSEL_EX1,
 ILSEL_EX2,
 ILSEL_EX3,
 ILSEL_EX4,

 ILSEL_FPGA2 = ILSEL_FPGA0,
 ILSEL_FPGA3 = ILSEL_FPGA1,
 ILSEL_EX5 = ILSEL_EX1,
 ILSEL_EX6 = ILSEL_EX2,
 ILSEL_EX7 = ILSEL_EX3,
 ILSEL_EX8 = ILSEL_EX4,
} ilsel_source_t;

#endif
