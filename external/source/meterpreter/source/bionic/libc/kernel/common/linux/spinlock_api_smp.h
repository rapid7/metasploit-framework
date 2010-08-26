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
#ifndef __LINUX_SPINLOCK_API_SMP_H
#define __LINUX_SPINLOCK_API_SMP_H

#ifndef __LINUX_SPINLOCK_H
#error "please don't include this file directly"
#endif

#define assert_spin_locked(x) BUG_ON(!spin_is_locked(x))

#endif
