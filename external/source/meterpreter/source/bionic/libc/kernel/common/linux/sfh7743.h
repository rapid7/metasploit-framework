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
#ifndef _LINUX_SFH7743_H_
#define _LINUX_SFH7743_H_

#include <linux/ioctl.h>

#define SFH7743_IO 0xA2

#define SFH7743_IOCTL_GET_ENABLE _IOR(SFH7743_IO, 0x00, char)
#define SFH7743_IOCTL_SET_ENABLE _IOW(SFH7743_IO, 0x01, char)

#endif
