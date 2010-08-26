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
#ifndef __LIS331DLH_H__
#define __LIS331DLH_H__

#include <linux/ioctl.h>  

#define LIS331DLH_IOCTL_BASE 77

#define LIS331DLH_IOCTL_SET_DELAY _IOW(LIS331DLH_IOCTL_BASE, 0, int)
#define LIS331DLH_IOCTL_GET_DELAY _IOR(LIS331DLH_IOCTL_BASE, 1, int)
#define LIS331DLH_IOCTL_SET_ENABLE _IOW(LIS331DLH_IOCTL_BASE, 2, int)
#define LIS331DLH_IOCTL_GET_ENABLE _IOR(LIS331DLH_IOCTL_BASE, 3, int)
#define LIS331DLH_IOCTL_SET_G_RANGE _IOW(LIS331DLH_IOCTL_BASE, 4, int)

#define LIS331DLH_G_2G 0x00
#define LIS331DLH_G_4G 0x10
#define LIS331DLH_G_8G 0x30

#endif

