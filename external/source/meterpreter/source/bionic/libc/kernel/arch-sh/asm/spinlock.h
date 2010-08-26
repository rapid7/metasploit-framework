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
#ifndef __ASM_SH_SPINLOCK_H
#define __ASM_SH_SPINLOCK_H

#define __raw_spin_is_locked(x) ((x)->lock <= 0)
#define __raw_spin_lock_flags(lock, flags) __raw_spin_lock(lock)
#define __raw_spin_unlock_wait(x)   do { cpu_relax(); } while ((x)->lock)

#define __raw_read_can_lock(x) ((x)->lock > 0)
#define __raw_write_can_lock(x) ((x)->lock == RW_LOCK_BIAS)
#define _raw_spin_relax(lock) cpu_relax()
#define _raw_read_relax(lock) cpu_relax()
#define _raw_write_relax(lock) cpu_relax()
#endif
