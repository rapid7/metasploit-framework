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
#ifndef __LINUX_BITMAP_H
#define __LINUX_BITMAP_H

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/string.h>

#define BITMAP_LAST_WORD_MASK(nbits)  (   ((nbits) % BITS_PER_LONG) ?   (1UL<<((nbits) % BITS_PER_LONG))-1 : ~0UL  )

#endif
#endif
