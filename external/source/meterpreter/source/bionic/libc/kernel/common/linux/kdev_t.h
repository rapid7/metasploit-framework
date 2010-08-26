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
#ifndef _LINUX_KDEV_T_H
#define _LINUX_KDEV_T_H

#define MAJOR(dev) ((dev)>>8)
#define MINOR(dev) ((dev) & 0xff)
#define MKDEV(ma,mi) ((ma)<<8 | (mi))
#endif
