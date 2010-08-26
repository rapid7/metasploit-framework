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
#ifndef __LINUX_KEYCHORD_H_
#define __LINUX_KEYCHORD_H_

#include <linux/input.h>

#define KEYCHORD_VERSION 1

struct input_keychord {

 __u16 version;

 __u16 id;

 __u16 count;

 __u16 keycodes[];
};

#endif
