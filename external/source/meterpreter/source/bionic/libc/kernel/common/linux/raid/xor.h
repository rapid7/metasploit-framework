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
#ifndef _XOR_H
#define _XOR_H

#include <linux/raid/md.h>

#define MAX_XOR_BLOCKS 5

struct xor_block_template {
 struct xor_block_template *next;
 const char *name;
 int speed;
 void (*do_2)(unsigned long, unsigned long *, unsigned long *);
 void (*do_3)(unsigned long, unsigned long *, unsigned long *,
 unsigned long *);
 void (*do_4)(unsigned long, unsigned long *, unsigned long *,
 unsigned long *, unsigned long *);
 void (*do_5)(unsigned long, unsigned long *, unsigned long *,
 unsigned long *, unsigned long *, unsigned long *);
};

#endif
