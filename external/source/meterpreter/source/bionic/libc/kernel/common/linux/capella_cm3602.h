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
#ifndef __LINUX_CAPELLA_CM3602_H
#define __LINUX_CAPELLA_CM3602_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define CAPELLA_CM3602_IOCTL_MAGIC 'c'
#define CAPELLA_CM3602_IOCTL_GET_ENABLED   _IOR(CAPELLA_CM3602_IOCTL_MAGIC, 1, int *)
#define CAPELLA_CM3602_IOCTL_ENABLE   _IOW(CAPELLA_CM3602_IOCTL_MAGIC, 2, int *)

#endif

