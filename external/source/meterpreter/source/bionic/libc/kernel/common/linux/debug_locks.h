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
#ifndef __LINUX_DEBUG_LOCKING_H
#define __LINUX_DEBUG_LOCKING_H

struct task_struct;

#define _RET_IP_ (unsigned long)__builtin_return_address(0)
#define _THIS_IP_ ({ __label__ __here; __here: (unsigned long)&&__here; })

#define DEBUG_LOCKS_WARN_ON(c)  ({   int __ret = 0;     if (unlikely(c)) {   if (debug_locks_off())   WARN_ON(1);   __ret = 1;   }   __ret;  })

#define SMP_DEBUG_LOCKS_WARN_ON(c) do { } while (0)

#define locking_selftest() do { } while (0)

#endif
