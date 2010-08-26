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
#ifndef _LINUX_RANDOM_H
#define _LINUX_RANDOM_H

#include <linux/ioctl.h>

#define RNDGETENTCNT _IOR( 'R', 0x00, int )

#define RNDADDTOENTCNT _IOW( 'R', 0x01, int )

#define RNDGETPOOL _IOR( 'R', 0x02, int [2] )

#define RNDADDENTROPY _IOW( 'R', 0x03, int [2] )

#define RNDZAPENTCNT _IO( 'R', 0x04 )

#define RNDCLEARPOOL _IO( 'R', 0x06 )

struct rand_pool_info {
 int entropy_count;
 int buf_size;
 __u32 buf[0];
};

#endif
