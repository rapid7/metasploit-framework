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
#ifndef _OMAP_CSMI_H_
#define _OMAP_CSMI_H_

#include <asm/ioctl.h>

#define OMAP_CSMI_TTY_ENABLE_ACK _IO('c', 0)
#define OMAP_CSMI_TTY_DISABLE_ACK _IO('c', 1)
#define OMAP_CSMI_TTY_READ_UNACKED _IOR('c', 2, int)
#define OMAP_CSMI_TTY_ACK _IOW('c', 3, int)
#define OMAP_CSMI_TTY_WAKEUP_AND_ACK _IOW('c', 4, int)

#endif
