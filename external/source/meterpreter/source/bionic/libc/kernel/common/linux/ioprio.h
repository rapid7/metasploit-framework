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
#ifndef IOPRIO_H
#define IOPRIO_H

#include <linux/sched.h>

#define IOPRIO_BITS (16)
#define IOPRIO_CLASS_SHIFT (13)
#define IOPRIO_PRIO_MASK ((1UL << IOPRIO_CLASS_SHIFT) - 1)

#define IOPRIO_PRIO_CLASS(mask) ((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask) ((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data) (((class) << IOPRIO_CLASS_SHIFT) | data)

#define ioprio_valid(mask) (IOPRIO_PRIO_CLASS((mask)) != IOPRIO_CLASS_NONE)

enum {
 IOPRIO_CLASS_NONE,
 IOPRIO_CLASS_RT,
 IOPRIO_CLASS_BE,
 IOPRIO_CLASS_IDLE,
};

#define IOPRIO_BE_NR (8)

enum {
 IOPRIO_WHO_PROCESS = 1,
 IOPRIO_WHO_PGRP,
 IOPRIO_WHO_USER,
};

#define IOPRIO_NORM (4)

#endif
