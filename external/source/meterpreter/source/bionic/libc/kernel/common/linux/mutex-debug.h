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
#ifndef __LINUX_MUTEX_DEBUG_H
#define __LINUX_MUTEX_DEBUG_H

#include <linux/linkage.h>
#include <linux/lockdep.h>

#define __DEBUG_MUTEX_INITIALIZER(lockname)   , .magic = &lockname

#define mutex_init(mutex)  do {   static struct lock_class_key __key;     __mutex_init((mutex), #mutex, &__key);  } while (0)

#endif
